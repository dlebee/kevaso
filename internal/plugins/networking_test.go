package plugins

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// declaring is a fake plugin under another name, declaring what it is told (nil: nothing).
type declaring struct {
	*kplugintest.Fake
	name string
	n    *kplugin.Networking
}

func (d *declaring) Info(context.Context) (kplugin.Info, error) {
	return kplugin.Info{Name: d.name, Version: "1.0.0", Protocol: kplugin.Protocol, Revision: kplugin.Revision, Networking: d.n}, nil
}

// both runs f against the registry (plugins registered over their sockets) and Static over the
// same declarations: the fake answers what the real one does.
func both(t *testing.T, f func(t *testing.T, n Networking)) {
	decl := map[string]*kplugin.Networking{"linode": kplugintest.FakeNetworking(), "old": nil}
	t.Run("registry", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "kpn")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		for name, n := range decl {
			if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
				t.Fatal(err)
			}
			serveNamed(t, filepath.Join(dir, name, kplugin.ControllerSocket), &declaring{Fake: kplugintest.New(), name: name, n: n})
		}
		r := &Registry{Dir: dir, Manifests: t.TempDir()}
		r.scan(context.Background(), dir)
		t.Cleanup(func() {
			for _, p := range r.All() {
				closeConn(p.Conn)
			}
		})
		if got := strings.Join(r.Providers(), ","); got != "linode,old" {
			t.Fatalf("registered %s", got)
		}
		f(t, r)
	})
	t.Run("static", func(t *testing.T) { f(t, Static(decl)) })
}

func TestNetworkingValidation(t *testing.T) {
	both(t, func(t *testing.T, n Networking) {
		// The fake declares in its own words; installed as linode, its domain is linode's.
		if err := n.ValidateServiceAnnotations("linode", map[string]string{"linode.kevaso.com/balancer": "edge", "kevaso.com/x": "y"}); err != nil {
			t.Errorf("good: %v", err)
		}
		err := n.ValidateServiceAnnotations("linode", map[string]string{"linode.kevaso.com/balancr": "edge"})
		var ae *kplugin.AnnotationError
		if !errors.As(err, &ae) || ae.Name != "linode.kevaso.com/balancr" || !strings.Contains(err.Error(), "provider linode: annotation linode.kevaso.com/balancr: not an annotation linode accepts on a service; did you mean linode.kevaso.com/balancer?") {
			t.Errorf("typo: %v", err)
		}
		if err := n.ValidateIPAnnotations("linode", map[string]string{"linode.kevaso.com/tag": "x"}); err != nil {
			t.Errorf("ip: %v", err)
		}
		if err := n.ValidateIPAnnotations("linode", map[string]string{"linode.kevaso.com/balancer-size": "large"}); err == nil {
			t.Error("a service's annotation accepted on an IP")
		}
		// A plugin that declares nothing: its annotations go to it unchecked.
		if err := n.ValidateServiceAnnotations("old", map[string]string{"old.kevaso.com/anything": "x"}); err != nil {
			t.Errorf("old: %v", err)
		}
		// No such provider: wrapped ErrNoProvider, naming the installed ones.
		err = n.ValidateServiceAnnotations("linod", nil)
		if !errors.Is(err, ErrNoProvider) || !strings.Contains(err.Error(), "provider linod: no such provider: installed are linode, old") {
			t.Errorf("unknown: %v", err)
		}
	})
}

func TestNetworkingCapabilities(t *testing.T) {
	both(t, func(t *testing.T, n Networking) {
		if n.CanFrontWithIP("linode") || n.CanFrontWithIP("old") || n.CanFrontWithIP("nope") {
			t.Error("front with IP: the fake's balancer has its own address")
		}
		if n.KeepsClientIP("linode") {
			t.Error("keeps client IP")
		}
		if err := n.ValidateLoadBalancer("linode"); err != nil {
			t.Error(err)
		}
		if err := n.ValidateLoadBalancer("old"); err == nil || !strings.Contains(err.Error(), "declares nothing about networking") {
			t.Errorf("old balancer: %v", err)
		}
		if err := n.ValidateProviderIP("linode", "us-ord"); err != nil {
			t.Error(err)
		}
		for region, says := range map[string]string{
			"":        "provider linode: an IP of type Provider needs a region (one of ca-central, us-ord)",
			"eu-west": "provider linode doesn't serve region eu-west (one of ca-central, us-ord)",
		} {
			if err := n.ValidateProviderIP("linode", region); err == nil || err.Error() != says {
				t.Errorf("region %q: %v, want %q", region, err, says)
			}
		}
		if err := n.ValidateProviderIP("nope", "us-ord"); !errors.Is(err, ErrNoProvider) {
			t.Errorf("unknown: %v", err)
		}
		r, err := n.Reach("linode")
		if err != nil || r.Scope != kplugin.FollowsRegion || !r.OwnHostsOnly || strings.Join(r.Regions, ",") != "ca-central,us-ord" {
			t.Errorf("reach %+v %v", r, err)
		}
		if _, err := n.Reach("old"); err == nil {
			t.Error("reach of a plugin that declares nothing")
		}
	})
}

func TestStaticDoesNothingCapableWithoutDeclaring(t *testing.T) {
	s := Static{"bare": &kplugin.Networking{}}
	if err := s.ValidateProviderIP("bare", "x"); err == nil || err.Error() != "provider bare doesn't make IPs of type Provider" {
		t.Errorf("ip: %v", err)
	}
	if err := s.ValidateLoadBalancer("bare"); err == nil || !strings.Contains(err.Error(), "doesn't make load balancers") {
		t.Errorf("lb: %v", err)
	}
	if err := s.ValidateServiceAnnotations("bare", map[string]string{"bare.kevaso.com/x": "1"}); err == nil || !strings.Contains(err.Error(), "(it accepts none)") {
		t.Errorf("annotations: %v", err)
	}
	if err := (Static{}).ValidateLoadBalancer("x"); err == nil || !strings.Contains(err.Error(), "none is installed") {
		t.Errorf("empty: %v", err)
	}
}

// A plugin declaring what Kevaso can't check is refused, saying what; one that is fine still
// registers beside it.
func TestABadNetworkingDeclarationIsRefused(t *testing.T) {
	var logged []string
	r := &Registry{Log: func(f string, a ...any) { logged = append(logged, f) }}
	bad := &declaring{Fake: kplugintest.New(), name: "bad", n: &kplugin.Networking{Annotations: []kplugin.Annotation{{Key: "size", Type: "enum"}}}}
	err := r.Add(context.Background(), bad)
	if err == nil || !strings.Contains(err.Error(), "it declares networking Kevaso can't check (annotation size: an enum needs values)") {
		t.Fatalf("bad: %v", err)
	}
	if err := r.Add(context.Background(), &declaring{Fake: kplugintest.New(), name: "good", n: kplugintest.FakeNetworking()}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.Providers(), ","); got != "good" {
		t.Fatalf("registered %s", got)
	}
}
