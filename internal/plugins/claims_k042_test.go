package plugins

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// named is a fake plugin under another name, serving what it is told.
type named struct {
	*kplugintest.Fake
	name    string
	storage []kplugin.Class
	lbs     []kplugin.Class
	dns     []string
}

func (n *named) Info(context.Context) (kplugin.Info, error) {
	return kplugin.Info{Name: n.name, Version: "1.0.0", Protocol: kplugin.Protocol, Revision: kplugin.Revision,
		Storage: n.storage, LoadBalancers: n.lbs, DNS: n.dns}, nil
}

// serveNamed serves p at sock until the test ends.
func serveNamed(t *testing.T, sock string, p kplugin.Plugin) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = kplugin.Serve(ctx, sock, p) }()
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() { cancel(); <-done })
}

// K-042: two plugins could serve one class or one DNS name, and the first in name order silently
// got every call (a DNS-only plugin listing another's storage class received its deletes); a
// socket reporting another plugin's name replaced it. Now a plugin is refused when it claims what
// a registered plugin serves, or a name that isn't its socket folder's (the name it was installed
// under), with both named; the one already serving keeps serving.
func TestASecondPluginForAClassOrNameIsRefused(t *testing.T) {
	block := []kplugin.Class{{Name: "acme-block"}}
	for _, tc := range []struct {
		name   string
		folder string // where the second is installed (its socket folder)
		second *named
		says   string
	}{
		{"storage class", "aaa", &named{name: "aaa", storage: block}, "storage class acme-block: plugin acme serves it already"},
		{"load-balancer class named like a storage class", "aaa", &named{name: "aaa", lbs: block}, "load-balancer class acme-block: plugin acme serves it already (a storage class)"},
		{"dns name", "aaa", &named{name: "aaa", dns: []string{"acme"}}, "dns provider acme: plugin acme serves it already"},
		{"another's plugin name", "aaa", &named{name: "acme"}, `answers as plugin acme, but it is installed as aaa`},
		{"a name not its own", "bbb", &named{name: "ccc"}, `answers as plugin ccc, but it is installed as bbb`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := os.MkdirTemp("", "kpc")
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			var l logs
			r := &Registry{Dir: dir, Log: l.logf}
			ctx := context.Background()
			serveNamed(t, filepath.Join(dir, "acme", "plugin.sock"), &named{Fake: kplugintest.New(), name: "acme", storage: block, dns: []string{"acme"}})
			r.scan(ctx, dir)
			if len(r.All()) != 1 {
				t.Fatalf("the first never registered: %s", l.all())
			}
			tc.second.Fake = kplugintest.New()
			serveNamed(t, filepath.Join(dir, tc.folder, "plugin.sock"), tc.second)
			for range 3 {
				r.scan(ctx, dir)
			}
			if p, _, ok := r.Storage("acme-block"); !ok || p.Info.Name != "acme" {
				t.Fatalf("the class isn't the first plugin's any more: %v\n%s", ok, l.all())
			}
			if p, ok := r.DNS("acme"); !ok || p.Info.Name != "acme" {
				t.Fatalf("the dns name isn't the first plugin's any more: %v\n%s", ok, l.all())
			}
			if n := len(r.All()); n != 1 {
				t.Fatalf("%d plugins registered, want only the first:\n%s", n, l.all())
			}
			got := l.all()
			if strings.Count(got, "refused") != 1 || !strings.Contains(got, tc.says) || !strings.Contains(got, filepath.Join(dir, tc.folder, "plugin.sock")) {
				t.Fatalf("log, want one refusal saying %q:\n%s", tc.says, got)
			}
		})
	}
}

// In-process plugins (Registry.Add) are refused the same way.
func TestAddRefusesAClassAnotherServes(t *testing.T) {
	r := &Registry{}
	ctx := context.Background()
	if err := r.Add(ctx, &named{Fake: kplugintest.New(), name: "acme", storage: []kplugin.Class{{Name: "acme-block"}}}); err != nil {
		t.Fatal(err)
	}
	err := r.Add(ctx, &named{Fake: kplugintest.New(), name: "other", storage: []kplugin.Class{{Name: "acme-block"}}})
	if err == nil || !strings.Contains(err.Error(), "storage class acme-block: plugin acme serves it already") {
		t.Fatalf("a second plugin for one class: %v", err)
	}
	if p, _, _ := r.Storage("acme-block"); p.Info.Name != "acme" {
		t.Fatalf("the class is %s's now", p.Info.Name)
	}
}
