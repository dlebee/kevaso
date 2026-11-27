package kplugin_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"kevaso.com/core/sdk/kplugin"
	pb "kevaso.com/core/sdk/kplugin/kpluginpb"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

func TestNetworkingRoundTrip(t *testing.T) {
	f := kplugintest.New()
	info, err := serve(t, f).Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(info.Networking, kplugintest.FakeNetworking()) {
		t.Fatalf("over the wire\n got %+v\nwant %+v", info.Networking, kplugintest.FakeNetworking())
	}
	// Declaring nothing (a plugin of revision 1, or one that leaves it out) stays nothing, not an
	// empty declaration: core then leaves its annotations to it.
	info, err = serve(t, infoOnly{}).Info(context.Background())
	if err != nil || info.Networking != nil {
		t.Fatalf("declared nothing, got %+v %v", info.Networking, err)
	}
	// An empty declaration (it makes nothing, accepts nothing) stays one.
	g := kplugintest.New()
	g.Networking = &kplugin.Networking{}
	info, err = serve(t, g).Info(context.Background())
	if err != nil || info.Networking == nil {
		t.Fatalf("declared it does nothing, got %+v %v", info.Networking, err)
	}
	// The IPv6 capability and the reason a provider can't float IPv6 cross the wire.
	for _, n := range []kplugin.Networking{{ProviderIPs: true, ProviderIPv6: true}, {ProviderIPs: true, NoProviderIPv6: "a /64 moves as one unit"}} {
		h := kplugintest.New()
		h.Networking = &n
		info, err = serve(t, h).Info(context.Background())
		if err != nil || !reflect.DeepEqual(*info.Networking, n) {
			t.Fatalf("over the wire\n got %+v %v\nwant %+v", info.Networking, err, n)
		}
	}
}

// A reservation says its family: a provider floating IPv6 is asked for IPv6 and gives one.
func TestAReservationCarriesItsFamily(t *testing.T) {
	f := kplugintest.New()
	f.Networking = kplugintest.FakeNetworking()
	f.Networking.ProviderIPv6 = true
	c := serve(t, f)
	st, err := c.ReserveAddress(context.Background(), kplugin.AddressReservation{Class: kplugintest.ClassIP, ID: "u6", Region: "ca-central", Family: "IPv6"})
	if err != nil || st.Address != "2001:db8:f::64" {
		t.Fatalf("IPv6 reservation: %+v %v", st, err)
	}
	st, err = c.ReserveAddress(context.Background(), kplugin.AddressReservation{Class: kplugintest.ClassIP, ID: "u4", Region: "ca-central"})
	if err != nil || st.Address != "203.0.113.100" {
		t.Fatalf("IPv4 reservation: %+v %v", st, err)
	}
}

// oldIdentity is a plugin built against an sdk of wire revision 1: its PluginInfo has no field 9.
type oldIdentity struct{ pb.UnimplementedIdentityServer }

func (oldIdentity) GetPluginInfo(context.Context, *pb.GetPluginInfoRequest) (*pb.PluginInfo, error) {
	return &pb.PluginInfo{Name: "old", Protocol: kplugin.Protocol, Revision: 1}, nil
}

func TestARevisionOnePluginDeclaresNothing(t *testing.T) {
	lis, sock := listen(t)
	s := grpc.NewServer()
	pb.RegisterIdentityServer(s, oldIdentity{})
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	r, err := pb.NewIdentityClient(conn).GetPluginInfo(context.Background(), &pb.GetPluginInfoRequest{})
	if err != nil || r.GetRevision() != 1 || r.GetNetworking() != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if kplugin.MinRevision > 1 {
		t.Fatal("core must still serve revision-1 plugins (the provider repos pin that sdk)")
	}
}

func TestNetworkingCheck(t *testing.T) {
	one, two := int64(1), int64(2)
	for _, tc := range []struct {
		name string
		n    kplugin.Networking
		says string // "" : fine
	}{
		{"fake", *kplugintest.FakeNetworking(), ""},
		{"nothing", kplugin.Networking{}, ""},
		{"reach", kplugin.Networking{Reach: "zone"}, `reach "zone"`},
		{"front without IPs", kplugin.Networking{FrontWithIP: true, LoadBalancers: true}, "frontWithIP needs both"},
		{"IPv6 without IPs", kplugin.Networking{ProviderIPv6: true}, "providerIPv6 needs providerIPs"},
		{"IPv6 and a reason it can't", kplugin.Networking{ProviderIPs: true, ProviderIPv6: true, NoProviderIPv6: "x"}, "noProviderIPv6 is the reason it can't"},
		{"a reason it can't float IPv6", kplugin.Networking{ProviderIPs: true, NoProviderIPv6: "a /64 moves as one unit"}, ""},
		{"region twice", kplugin.Networking{Regions: []string{"a", "a"}}, `region "a" empty or twice`},
		{"key with domain", kplugin.Networking{Annotations: []kplugin.Annotation{{Key: "linode.kevaso.com/x"}}}, "without the domain"},
		{"key twice", kplugin.Networking{Annotations: []kplugin.Annotation{{Key: "a"}, {Key: "a"}}}, "declared twice"},
		{"bad pattern", kplugin.Networking{Annotations: []kplugin.Annotation{{Key: "a", Pattern: "("}}}, "annotation a: pattern"},
		{"pattern on int", kplugin.Networking{Annotations: []kplugin.Annotation{{Key: "a", Type: "int", Pattern: "x"}}}, "a pattern is for type string"},
		{"enum without values", kplugin.Networking{Annotations: []kplugin.Annotation{{Key: "a", Type: "enum"}}}, "needs values"},
		{"values on string", kplugin.Networking{Annotations: []kplugin.Annotation{{Key: "a", Values: []string{"x"}}}}, "values are for type enum"},
		{"min above max", kplugin.Networking{Annotations: []kplugin.Annotation{{Key: "a", Type: "int", Min: &two, Max: &one}}}, "min 2 above max 1"},
		{"min on bool", kplugin.Networking{Annotations: []kplugin.Annotation{{Key: "a", Type: "bool", Min: &one}}}, "min and max are for type int"},
		{"type", kplugin.Networking{Annotations: []kplugin.Annotation{{Key: "a", Type: "float"}}}, `type "float"`},
		{"on", kplugin.Networking{Annotations: []kplugin.Annotation{{Key: "a", On: []string{"silo"}}}}, `on "silo"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.n.Check()
			if tc.says == "" && err != nil || tc.says != "" && (err == nil || !strings.Contains(err.Error(), tc.says)) {
				t.Errorf("Check: %v, want %q", err, tc.says)
			}
		})
	}
	var nothing *kplugin.Networking
	if err := nothing.Check(); err != nil {
		t.Errorf("nil: %v", err)
	}
}

func TestValidateAnnotations(t *testing.T) {
	n := kplugintest.FakeNetworking()
	const d = "fake.kevaso.com/"
	for _, tc := range []struct {
		name string
		on   string
		a    map[string]string
		says []string // one per error, in order; nil: fine
	}{
		{"fine", kplugin.OnService, map[string]string{d + "balancer": "edge", d + "balancer-size": "large", d + "max-connections": "10000", d + "proxy-protocol": "false"}, nil},
		{"others' domains and core's aren't its business", kplugin.OnService, map[string]string{"linode.kevaso.com/nodebalancer": "x", "kevaso.com/owner": "y", "fake-work.kevaso.com/z": "1"}, nil},
		{"misspelled", kplugin.OnService, map[string]string{d + "balancr": "edge"},
			[]string{"annotation fake.kevaso.com/balancr: not an annotation fake accepts on a service; did you mean fake.kevaso.com/balancer? (it accepts fake.kevaso.com/balancer, fake.kevaso.com/balancer-size, fake.kevaso.com/max-connections, fake.kevaso.com/proxy-protocol)"}},
		{"nothing like it", kplugin.OnService, map[string]string{d + "colour": "red"}, []string{"fake.kevaso.com/colour: not an annotation fake accepts on a service (it accepts"}},
		{"bad enum", kplugin.OnService, map[string]string{d + "balancer-size": "huge"}, []string{`annotation fake.kevaso.com/balancer-size: "huge": want one of small, medium, large`}},
		{"bad int", kplugin.OnService, map[string]string{d + "max-connections": "lots"}, []string{`"lots" isn't a whole number`}},
		{"int too big", kplugin.OnService, map[string]string{d + "max-connections": "10001"}, []string{"10001 is above 10000"}},
		{"int too small", kplugin.OnService, map[string]string{d + "max-connections": "0"}, []string{"0 is below 1"}},
		{"bad bool", kplugin.OnService, map[string]string{d + "proxy-protocol": "yes"}, []string{`"yes": want true or false`}},
		{"pattern is the whole value", kplugin.OnService, map[string]string{d + "balancer": "Edge 1"}, []string{`"Edge 1" doesn't match`}},
		{"an IP's annotation on a service", kplugin.OnService, map[string]string{d + "tag": "x"}, []string{"fake.kevaso.com/tag: it goes on ip, not on a service"}},
		{"on an IP", kplugin.OnIP, map[string]string{d + "tag": "x"}, nil},
		{"a service's on an IP", kplugin.OnIP, map[string]string{d + "balancer": "x"}, []string{"fake.kevaso.com/balancer: it goes on service, not on an IP (it accepts fake.kevaso.com/tag)"}},
		{"two, sorted", kplugin.OnService, map[string]string{d + "zz": "1", d + "balancer-size": "huge"}, []string{"balancer-size", "zz"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := n.ValidateAnnotations("fake", tc.on, tc.a)
			if tc.says == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted, want %q", tc.says)
			}
			lines := strings.Split(err.Error(), "\n")
			if len(lines) != len(tc.says) {
				t.Fatalf("%d errors, want %d: %v", len(lines), len(tc.says), err)
			}
			for i, s := range tc.says {
				if !strings.Contains(lines[i], s) {
					t.Errorf("error %d: %q, want %q", i, lines[i], s)
				}
			}
			var ae *kplugin.AnnotationError
			if !errors.As(err, &ae) || !strings.HasPrefix(ae.Name, d) {
				t.Errorf("not an AnnotationError naming the annotation: %#v", err)
			}
		})
	}
	// A second account reads its own domain: the same declaration, another name.
	if err := n.ValidateAnnotations("fake-work", kplugin.OnService, map[string]string{"fake-work.kevaso.com/balancr": "x"}); err == nil || !strings.Contains(err.Error(), "did you mean fake-work.kevaso.com/balancer?") {
		t.Errorf("second account: %v", err)
	}
	var nothing *kplugin.Networking
	if err := nothing.ValidateAnnotations("old", kplugin.OnService, map[string]string{"old.kevaso.com/anything": "x"}); err != nil {
		t.Errorf("declares nothing, checks nothing: %v", err)
	}
}

// listen is a unix socket in a short temporary folder (removed after whatever serves on it stops:
// cleanups run last-registered first).
func listen(t *testing.T) (net.Listener, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kpl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "plugin.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	return lis, sock
}
