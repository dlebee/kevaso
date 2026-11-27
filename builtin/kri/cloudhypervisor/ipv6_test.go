package cloudhypervisor

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"kevaso.com/core/sdk/kri"

	"kevaso.com/core/internal/mesh"
)

func withNetwork(t *testing.T, p4 string) {
	t.Helper()
	old := Network
	SetNetwork(netip.MustParsePrefix(p4))
	t.Cleanup(func() { SetNetwork(old) })
}

// The runtime's silo IPv6 is the control plane's (mesh.SiloIPv6): kni and status.siloIPv6 agree.
func TestSiloNet6IsTheMeshRule(t *testing.T) {
	withNetwork(t, "10.64.3.0/24")
	const sub6, gw6 = "fd12:3456:789a:3::/64", "fd12:3456:789a:3::1"
	for _, ip := range []string{"10.64.3.2", "10.64.3.17", "10.64.3.254"} {
		got, g, ok := SiloNet6(sub6, gw6, netip.MustParseAddr(ip))
		want, wok := mesh.SiloIPv6(sub6, Network.String(), ip)
		if !ok || !wok || got.String() != want || g.String() != gw6 {
			t.Errorf("%s: %s via %s %v, mesh says %s %v", ip, got, g, ok, want, wok)
		}
	}
	for _, c := range []struct{ sub6, gw6, ip string }{
		{sub6, gw6, "10.64.4.2"},                                  // not in the host's subnet
		{sub6, gw6, "10.64.3.1"},                                  // the IPv4 gateway
		{"", "", "10.64.3.2"},                                     // no IPv6 on the host
		{sub6, "", "10.64.3.2"},                                   // no gateway
		{"fd12:3456:789a::/48", "fd12:3456:789a::1", "10.64.3.2"}, // not a /64
		{sub6, "fd12:3456:789a:4::1", "10.64.3.2"},                // gateway outside it
		{sub6, "fd12:3456:789a:3::", "10.64.3.2"},                 // gateway is the network
		{sub6, "fd12:3456:789a:3::2", "10.64.3.2"},                // gateway is the silo's address
		{"10.64.3.0/24", "10.64.3.1", "10.64.3.2"},                // IPv4
		{"::ffff:10.0.0.0/64", "::ffff:10.0.0.1", "10.64.3.2"},    // mapped
	} {
		if a, g, ok := SiloNet6(c.sub6, c.gw6, netip.MustParseAddr(c.ip)); ok {
			t.Errorf("%+v: got %s via %s", c, a, g)
		}
	}
}

// With no silo IPv6 the guest's network config is exactly what it was before the IPv6 effort.
func TestNetworkConfigIPv4Only(t *testing.T) {
	got := NetworkConfig("52:4b:00:00:00:01", netip.MustParseAddr("10.64.0.2"), netip.Addr{}, netip.Addr{}, "web3")
	want := `version: 2
ethernets:
  nic0:
    match: { macaddress: "52:4b:00:00:00:01" }
    set-name: eth0
    addresses: [10.64.0.2/24]
    routes: [{ to: default, via: 10.64.0.1 }]
    nameservers: { addresses: [10.64.0.1], search: [web3.kevaso, kevaso] }
`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

// With silo IPv6: both addresses, both default routes, router advertisements off; DNS on IPv4.
func TestNetworkConfigIPv6(t *testing.T) {
	withNetwork(t, "10.64.3.0/24")
	ip := netip.MustParseAddr("10.64.3.17")
	ip6, gw6, _ := SiloNet6("fd12:3456:789a:3::/64", "fd12:3456:789a:3::1", ip)
	got := NetworkConfig("52:4b:00:00:00:01", ip, ip6, gw6, "web3")
	want := `version: 2
ethernets:
  nic0:
    match: { macaddress: "52:4b:00:00:00:01" }
    set-name: eth0
    addresses: [10.64.3.17/24, "fd12:3456:789a:3::11/64"]
    routes: [{ to: default, via: 10.64.3.1 }, { to: "::/0", via: "fd12:3456:789a:3::1" }]
    accept-ra: false
    nameservers: { addresses: [10.64.3.1], search: [web3.kevaso, kevaso] }
`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	var doc struct {
		Ethernets map[string]struct {
			Addresses []string `yaml:"addresses"`
			Routes    []struct {
				To  string `yaml:"to"`
				Via string `yaml:"via"`
			} `yaml:"routes"`
			AcceptRA *bool `yaml:"accept-ra"`
		} `yaml:"ethernets"`
	}
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatal(err)
	}
	e := doc.Ethernets["nic0"]
	if len(e.Addresses) != 2 || e.Addresses[1] != "fd12:3456:789a:3::11/64" || len(e.Routes) != 2 || e.Routes[1].Via != "fd12:3456:789a:3::1" ||
		e.AcceptRA == nil || *e.AcceptRA {
		t.Fatalf("parsed %+v", e)
	}
}

func spec6(name string) kri.Spec {
	sp := spec(name)
	sp.Subnet6, sp.Gateway6 = "fd12:3456:789a::/64", "fd12:3456:789a::1"
	return sp
}

// A VM whose spec has IPv6: its seed's network config and its state ("ip6") carry the address.
func TestCreateGivesTheGuestIPv6(t *testing.T) {
	h := newFakeHost()
	r := newRuntime(t, h)
	if err := r.Create(context.Background(), spec6("web")); err != nil {
		t.Fatal(err)
	}
	st, ok := r.state(id("web"))
	if !ok || st.IP != "10.64.0.2" || st.IP6 != "fd12:3456:789a::2" || st.Gateway6 != "fd12:3456:789a::1" {
		t.Fatalf("state %+v", st)
	}
	n := NamesFor(id("web"))
	nc := string(h.files[n.Dir+"/network-config"])
	if nc != NetworkConfig(st.MAC, netip.MustParseAddr("10.64.0.2"), netip.MustParseAddr("fd12:3456:789a::2"), netip.MustParseAddr("fd12:3456:789a::1"), "dev") {
		t.Fatalf("network-config:\n%s", nc)
	}
	var raw map[string]any
	if err := json.Unmarshal(h.files[n.Dir+"/silo.json"], &raw); err != nil || raw["ip6"] != "fd12:3456:789a::2" {
		t.Fatalf("silo.json %s (%v): the worker reads ip6", h.files[n.Dir+"/silo.json"], err)
	}
}

func TestCreateWithoutIPv6(t *testing.T) {
	h := newFakeHost()
	r := newRuntime(t, h)
	if err := r.Create(context.Background(), spec("web")); err != nil {
		t.Fatal(err)
	}
	st, _ := r.state(id("web"))
	if st.IP6 != "" || st.Gateway6 != "" || strings.Contains(string(h.files[NamesFor(id("web")).Dir+"/silo.json"]), "ip6") {
		t.Fatalf("IPv6 %+v", st)
	}
}

// A VM made without IPv6 gets it with its next seed (a reset: a new instance, whose network
// config the guest takes); the guest host key's reseed keeps what the state has.
func TestResetGivesAnOlderGuestIPv6(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.Reset(ctx, spec6("web")); err != nil {
		t.Fatal(err)
	}
	st, _ := r.state(sp.ID)
	nc := string(h.files[NamesFor(sp.ID).Dir+"/network-config"])
	ip6, gw6 := st.net6()
	if st.IP6 != "fd12:3456:789a::2" || nc != NetworkConfig(st.MAC, netip.MustParseAddr(st.IP), ip6, gw6, "dev") {
		t.Fatalf("after reset: %q\n%s", st.IP6, nc)
	}
}
