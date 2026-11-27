package worker

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/hostreset"
	"kevaso.com/core/internal/store"
)

// The IPv6 effort, wave 2 (worker wiring): what the worker gives kni and the host for IPv6.

func host6() *v1.Host {
	h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "metal-1"}, Spec: v1.HostSpec{ExternalIP: "198.51.100.10", ExternalIPv6: "2001:db8:e::10",
		Addresses: []v1.HostAddress{{Name: "mail6", Kind: v1.NetworkExternal, Address: "2001:db8:e::21"}}}}
	h.Status.Network.SiloSubnet, h.Status.Network.SiloSubnetIPv6 = "10.64.0.0/24", "fd00:aa:bb:2::/64"
	return h
}

func web6() *v1.Silo {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev", UID: "u-web"}}
	s.Spec.Ports = []v1.SiloPort{{Name: "https", Port: 8443}}
	s.Spec.Services = []v1.SiloService{{Name: "web", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: v1.NetworkExternal},
		Ports: []v1.ServicePort{{Port: "https", As: 443}}}}
	s.Status.Host, s.Status.SiloIP, s.Status.SiloIPv6, s.Status.Phase = "metal-1", "10.64.0.2", "fd00:aa:bb:2::2", "Running"
	return s
}

func generate(t *testing.T, v kni.Host) string {
	t.Helper()
	text, problems := kni.Generate(v)
	if len(problems) > 0 {
		t.Fatalf("problems: %v", problems)
	}
	return text
}

func TestNetworkViewIPv6(t *testing.T) {
	h, s := host6(), web6()
	v := NetworkView("metal-1", h, []*v1.Silo{s}, nil, nil)
	if v.Subnet6.String() != "fd00:aa:bb:2::/64" || v.Gateway6.String() != "fd00:aa:bb:2::1" || v.ExternalIPv6.String() != "2001:db8:e::10" {
		t.Fatalf("subnet6 %v gateway6 %v external6 %v", v.Subnet6, v.Gateway6, v.ExternalIPv6)
	}
	if got := v.Local[0].IP6.String(); got != "fd00:aa:bb:2::2" {
		t.Fatalf("silo IPv6 %s", got)
	}
	text := generate(t, v)
	for _, want := range []string{
		"ip6 daddr 2001:db8:e::10 tcp dport 443 dnat ip6 to [fd00:aa:bb:2::2]:8443",
		`ip6 saddr fd00:aa:bb:2::/64 oifname != "kvbr0" masquerade`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in the rules", want)
		}
	}

	// A host without a global IPv6 address of its own is IPv4 only: no IPv6 silo subnet, no
	// silo IPv6, and the ruleset has no IPv6 twin.
	h4 := host6()
	h4.Spec.ExternalIPv6 = ""
	v4 := NetworkView("metal-1", h4, []*v1.Silo{s}, nil, nil)
	if v4.Subnet6.IsValid() || v4.Gateway6.IsValid() || v4.Local[0].IP6.IsValid() {
		t.Fatalf("IPv4-only host: %+v", v4)
	}
	if text := generate(t, v4); strings.Contains(text, "dnat ip6") || strings.Contains(text, "fd00:aa:bb:2") {
		t.Error("an IPv4-only host has IPv6 rules")
	}

	// A silo address outside the host's /64 is not taken.
	s2 := web6()
	s2.Status.SiloIPv6 = "fd00:aa:bb:3::2"
	if NetworkView("metal-1", h, []*v1.Silo{s2}, nil, nil).Local[0].IP6.IsValid() {
		t.Error("a silo IPv6 address outside the host's /64 was taken")
	}
}

func TestSiloNetwork6(t *testing.T) {
	for _, c := range []struct {
		name, ext6, sub6 string
		ok               bool
	}{
		{"both", "2001:db8:e::10", "fd00:aa:bb:2::/64", true},
		{"no external IPv6", "", "fd00:aa:bb:2::/64", false},
		{"no subnet", "2001:db8:e::10", "", false},
		{"not a /64", "2001:db8:e::10", "fd00:aa:bb:2::/60", false},
		{"not unique local", "2001:db8:e::10", "2001:db8:5::/64", false},
		{"external is unique local", "fd00::10", "fd00:aa:bb:2::/64", false},
		{"external is IPv4", "198.51.100.10", "fd00:aa:bb:2::/64", false},
	} {
		h := host6()
		h.Spec.ExternalIPv6, h.Status.Network.SiloSubnetIPv6 = c.ext6, c.sub6
		if _, _, ok := SiloNetwork6(h); ok != c.ok {
			t.Errorf("%s: ok %v", c.name, ok)
		}
	}
	if _, _, ok := SiloNetwork6(nil); ok {
		t.Error("nil host")
	}
}

// One IP, one family: a kept IPv6 Host IP opens its service on its IPv6 address, is the silo's
// IPv6 source (its IPv4 one stays the host's), goes on the uplink, and no silo reaches the host
// on it.
func TestWithIPsIPv6(t *testing.T) {
	h := host6()
	s := web6()
	s.Spec.Services = append(s.Spec.Services, v1.SiloService{Name: "web6", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "edge6"},
		Ports: []v1.ServicePort{{Port: "https", As: 443}}})
	s.Spec.Network.Egress.Source = &v1.EgressSource{IP: "edge6"}
	ip := hostIP("edge6", "dev", "mail6", "2001:db8:e::21", "metal-1", "u-web")
	ip.Spec.Family = v1.FamilyIPv6
	v := WithIPs(NetworkView("metal-1", h, []*v1.Silo{s}, nil, nil), "metal-1", h, []*v1.Silo{s}, []*v1.IP{ip})
	ks := v.Local[0]
	if ks.Addrs["web6"].String() != "2001:db8:e::21" || ks.EgressIPv6.String() != "2001:db8:e::21" || ks.EgressIP.IsValid() {
		t.Fatalf("addrs %v egress %v egress6 %v", ks.Addrs, ks.EgressIP, ks.EgressIPv6)
	}
	if !slices.Contains(v.OwnIPs, netip.MustParseAddr("2001:db8:e::21")) {
		t.Errorf("own IPs %v", v.OwnIPs)
	}
	if held := HeldAddresses("metal-1", []*v1.Silo{s}, []*v1.IP{ip}); !slices.Equal(held, []string{"2001:db8:e::21"}) {
		t.Errorf("held %v", held)
	}
	text := generate(t, v)
	for _, want := range []string{
		"ip6 daddr 2001:db8:e::21 tcp dport 443 dnat ip6 to [fd00:aa:bb:2::2]:8443",
		`ip6 saddr fd00:aa:bb:2::2 oifname != "kvbr0" snat ip6 to 2001:db8:e::21`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in the rules", want)
		}
	}
	// A Provider IPv6 IP is not here (no provider floats single IPv6 addresses).
	pip := hostIP("edge6", "dev", "", "2001:db8:e::99", "", "u-web")
	pip.Spec.Type, pip.Spec.Family = v1.IPTypeProvider, v1.FamilyIPv6
	if a := WithIPs(NetworkView("metal-1", h, []*v1.Silo{s}, nil, nil), "metal-1", h, []*v1.Silo{s}, []*v1.IP{pip}).Local[0]; a.Addrs["web6"].IsValid() || a.EgressIPv6.IsValid() {
		t.Errorf("a Provider IPv6 IP is used: %+v", a)
	}
}

func TestHostAddr(t *testing.T) {
	for in, ok := range map[string]bool{
		"198.51.100.4": true, "2001:db8:e::21": true, "::ffff:198.51.100.4": true,
		"fd00:aa:bb:2::2": false, "fe80::1": false, "169.254.1.1": false, "::": false, "::1": false, "ff02::1": false, "": false, "fe80::1%eth0": false,
	} {
		if _, got := hostAddr(in); got != ok {
			t.Errorf("hostAddr(%q) = %v", in, got)
		}
	}
	if v4, v6 := split46([]string{"198.51.100.4", "2001:db8:e::21", "198.51.100.4", "junk"}); !slices.Equal(v4, []string{"198.51.100.4"}) || v6[netip.MustParseAddr("2001:db8:e::21")] != 128 || len(v6) != 1 {
		t.Errorf("split46: %v %v", v4, v6)
	}
}

// The runtime's state file names the silo's IPv6 address ("ip6"): its port is bound to it, and
// the state wins over the status like the IPv4 address does.
func TestBindingIPv6(t *testing.T) {
	s := web6()
	n := cloudhypervisor.NamesFor(idOfSilo(s))
	files := stateFiles{n.Dir + "/silo.json": `{"id":{"namespace":"dev","name":"web","uid":"u-web"},"ip":"10.64.0.2","ip6":"fd00:aa:bb:2::2"}`}
	bound := LocalBindings(files)
	if b := bound[n.Tap]; b.IP6.String() != "fd00:aa:bb:2::2" {
		t.Fatalf("bound %+v", bound)
	}
	s.Status.SiloIPv6 = ""
	v := WithBindings(NetworkView("metal-1", host6(), []*v1.Silo{s}, nil, nil), bound)
	if v.Local[0].IP6.String() != "fd00:aa:bb:2::2" {
		t.Fatalf("view %+v", v.Local[0])
	}
	bs := kni.Bindings(v.Local)
	if len(bs) != 1 || bs[0].IP6.String() != "fd00:aa:bb:2::2" {
		t.Fatalf("bindings %+v", bs)
	}
	// A port made without one sends no IPv6, whatever the status says.
	files[n.Dir+"/silo.json"] = `{"id":{"namespace":"dev","name":"web","uid":"u-web"},"ip":"10.64.0.2"}`
	s.Status.SiloIPv6 = "fd00:aa:bb:2::2"
	if v := WithBindings(NetworkView("metal-1", host6(), []*v1.Silo{s}, nil, nil), LocalBindings(files)); v.Local[0].IP6.IsValid() {
		t.Errorf("an IPv6 address with no binding: %+v", v.Local[0])
	}
	// Outside the host's /64 (a stale state): none.
	files[n.Dir+"/silo.json"] = `{"id":{"namespace":"dev","name":"web","uid":"u-web"},"ip":"10.64.0.2","ip6":"fd00:aa:bb:9::2"}`
	if v := WithBindings(NetworkView("metal-1", host6(), []*v1.Silo{s}, nil, nil), LocalBindings(files)); v.Local[0].IP6.IsValid() {
		t.Errorf("an IPv6 address outside the /64: %+v", v.Local[0])
	}
}

func TestRouteSrc6(t *testing.T) {
	for out, want := range map[string]string{
		"2606:4700:4700::1111 from :: via fe80::1 dev eth0 proto ra src 2001:db8:e::10 metric 100 pref medium": "2001:db8:e::10",
		"2606:4700:4700::1111 from :: via fd00::1 dev eth0 src fd00::5 metric 1024 pref medium":                "",
		"2606:4700:4700::1111 from :: dev eth0 src fe80::5 metric 1024":                                        "",
		"": "",
	} {
		if got := routeSrc6(out); got != want {
			t.Errorf("routeSrc6(%q) = %q, want %q", out, got, want)
		}
	}
}

// fakeIP is `ip` on a host: the addresses on each interface. Like iproute2 6.1, it refuses
// an address protocol.
type fakeIP struct {
	mu    sync.Mutex
	addrs map[string][]string // iface → "PREFIX"
	calls []string
	sys   map[string]string
}

func (f *fakeIP) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	switch {
	case strings.HasPrefix(cmd, "ip link show "):
		if _, ok := f.addrs[args[2]]; !ok {
			return nil, errors.New("does not exist")
		}
		return nil, nil
	case strings.HasPrefix(cmd, "ip -6 -o addr show dev "):
		var b strings.Builder
		for _, a := range f.addrs[args[5]] {
			b.WriteString("2: " + args[5] + "    inet6 " + a + " scope global \\       valid_lft forever preferred_lft forever\n")
		}
		return []byte(b.String()), nil
	case strings.HasPrefix(cmd, "ip -6 addr add "):
		if slices.Contains(args, "proto") {
			return []byte(`Error: either "local" is duplicate, or "proto" is a garbage.`), errors.New("exit status 255")
		}
		if slices.Contains(f.addrs[args[5]], args[3]) {
			return []byte("RTNETLINK answers: File exists"), errors.New("exit status 2")
		}
		f.addrs[args[5]] = append(f.addrs[args[5]], args[3])
		return nil, nil
	case strings.HasPrefix(cmd, "ip -6 addr del "):
		if !slices.Contains(f.addrs[args[5]], args[3]) {
			return []byte("RTNETLINK answers: Cannot assign requested address"), errors.New("exit status 2")
		}
		f.addrs[args[5]] = slices.DeleteFunc(f.addrs[args[5]], func(a string) bool { return a == args[3] })
		return nil, nil
	}
	return nil, errors.New("unexpected " + cmd)
}

func withFakeIP(t *testing.T, f *fakeIP) {
	r, rs, ws, l := run6, readSysctl, writeSysctl, Ledger6
	run6 = f.run
	Ledger6 = filepath.Join(t.TempDir(), "run", "ipv6-addresses")
	readSysctl = func(p string) (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if v, ok := f.sys[p]; ok {
			return v, nil
		}
		return "", errors.New("no " + p)
	}
	writeSysctl = func(p, v string) error { f.mu.Lock(); defer f.mu.Unlock(); f.sys[p] = v; return nil }
	t.Cleanup(func() { run6, readSysctl, writeSysctl, Ledger6 = r, rs, ws, l })
}

// The uplink's held IPv6 addresses: in the ledger before they are added, deprecated /128s; one
// not wanted any more is taken off (here or on an earlier uplink) and leaves the ledger; the host's
// own addresses are never touched.
func TestSyncUplink6KeepsOnlyOurs(t *testing.T) {
	f := &fakeIP{addrs: map[string][]string{"eth0": {"2001:db8:e::10/64", "2001:db8:e::99/128"}, "eth1": {"2001:db8:f::5/128"}}, sys: map[string]string{}}
	withFakeIP(t, f)
	if err := os.MkdirAll(filepath.Dir(Ledger6), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Ledger6, []byte("eth0 2001:db8:e::99/128\neth1 2001:db8:f::5/128\njunk line here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := map[netip.Addr]int{netip.MustParseAddr("2001:db8:e::21"): 128}
	if err := syncUplink6(context.Background(), "eth0", want); err != nil {
		t.Fatal(err)
	}
	if got := f.addrs["eth0"]; !slices.Equal(got, []string{"2001:db8:e::10/64", "2001:db8:e::21/128"}) || len(f.addrs["eth1"]) != 0 {
		t.Fatalf("addresses %v (calls %v)", f.addrs, f.calls)
	}
	if !slices.Contains(f.calls, "ip -6 addr add 2001:db8:e::21/128 dev eth0 nodad preferred_lft 0") {
		t.Errorf("not added deprecated: %v", f.calls)
	}
	if b, _ := os.ReadFile(Ledger6); string(b) != "eth0 2001:db8:e::21/128\n" {
		t.Errorf("ledger %q", b)
	}
	// Again: nothing to do but look.
	f.calls = nil
	if err := syncUplink6(context.Background(), "eth0", want); err != nil || len(f.calls) != 1 {
		t.Errorf("calls %v, %v", f.calls, err)
	}
	// Someone deleted it by hand: it comes back.
	f.addrs["eth0"] = f.addrs["eth0"][:1]
	if err := syncUplink6(context.Background(), "eth0", want); err != nil || len(f.addrs["eth0"]) != 2 {
		t.Errorf("addresses %v, %v", f.addrs, err)
	}
	// Nothing wanted: off, and out of the ledger.
	if err := syncUplink6(context.Background(), "eth0", nil); err != nil || !slices.Equal(f.addrs["eth0"], []string{"2001:db8:e::10/64"}) {
		t.Errorf("addresses %v, %v", f.addrs, err)
	}
	if b, _ := os.ReadFile(Ledger6); len(b) != 0 {
		t.Errorf("ledger %q", b)
	}
	if hostreset.Ledger6 != ledger6Path {
		t.Errorf("kvoadm reset reads %s, the worker writes %s", hostreset.Ledger6, ledger6Path)
	}
}

func TestSyncBridge6(t *testing.T) {
	conf := "/proc/sys/net/ipv6/conf/"
	f := &fakeIP{addrs: map[string][]string{cloudhypervisor.Bridge: {"fd00:aa:bb:9::1/64"}, "eth0": {"2001:db8:e::10/64"}},
		sys: map[string]string{conf + "all/forwarding": "0", conf + "eth0/accept_ra": "1", conf + cloudhypervisor.Bridge + "/accept_ra": "1",
			conf + cloudhypervisor.Bridge + "/disable_ipv6": "0"}}
	withFakeIP(t, f)
	if err := syncBridge6(context.Background(), host6(), "eth0"); err != nil {
		t.Fatal(err)
	}
	if got := f.addrs[cloudhypervisor.Bridge]; !slices.Equal(got, []string{"fd00:aa:bb:2::1/64"}) {
		t.Fatalf("bridge %v (calls %v)", got, f.calls)
	}
	if f.sys[conf+"all/forwarding"] != "1" || f.sys[conf+"eth0/accept_ra"] != "2" || f.sys[conf+cloudhypervisor.Bridge+"/accept_ra"] != "0" {
		t.Fatalf("sysctls %v", f.sys)
	}
	if !slices.Equal(f.addrs["eth0"], []string{"2001:db8:e::10/64"}) {
		t.Fatalf("the uplink was touched: %v", f.addrs["eth0"])
	}
	// The host loses its IPv6: the gateway goes, forwarding stays (kvoadm reset puts it back).
	h := host6()
	h.Spec.ExternalIPv6 = ""
	if err := syncBridge6(context.Background(), h, "eth0"); err != nil {
		t.Fatal(err)
	}
	if got := f.addrs[cloudhypervisor.Bridge]; len(got) != 0 {
		t.Fatalf("bridge %v", got)
	}
	// No bridge yet: nothing, no error.
	delete(f.addrs, cloudhypervisor.Bridge)
	f.calls = nil
	if err := syncBridge6(context.Background(), host6(), "eth0"); err != nil || len(f.calls) != 1 {
		t.Fatalf("no bridge: %v, %v", f.calls, err)
	}
}

// The host's global IPv6 address, detected, is reported in status.network.externalIPv6 (as the
// host itself: a worker writes no spec) and is the host's externalIPv6 unless spec.externalIPv6 is
// set; nothing detected leaves the host IPv4 only.
func TestUpdateHostDetectsIPv6(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	mk := func(name, ext6 string) {
		h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{InternalIP: "10.0.0.5", ExternalIPv6: ext6, Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
		if err := c.Create(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", "")
	mk("b", "2001:db8:e::99")
	mk("c", "")
	for _, x := range []struct{ host, detected, want string }{
		{"a", "2001:db8:e::10", "2001:db8:e::10"},
		{"b", "2001:db8:e::10", "2001:db8:e::99"},
		{"c", "", ""},
	} {
		cfg := Config{HostName: x.host, Log: t.Logf, DetectIPv6: func(context.Context) string { return x.detected }}
		h, err := UpdateHost(ctx, c, cfg, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var got v1.Host
		if err := c.Get(ctx, "Host", "", x.host, &got); err != nil {
			t.Fatal(err)
		}
		if got.ExternalIPv6() != x.want || h.ExternalIPv6() != x.want || got.Status.Network.ExternalIPv6 != x.detected {
			t.Errorf("host %s: externalIPv6 %q (returned %q, found %q), want %q", x.host, got.ExternalIPv6(), h.ExternalIPv6(), got.Status.Network.ExternalIPv6, x.want)
		}
	}
}
