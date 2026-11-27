package kni

import (
	"math/rand"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// The generated text, IPv6 twins included, checked by the real nft (`nft -c -f`: parsed and
// validated by the kernel, nothing loaded). Linux with nft and CAP_NET_ADMIN only, so it runs
// when asked: KNI_REAL_NFT=1, in a network namespace of its own on a lab machine:
//
//	GOWORK=off GOOS=linux GOARCH=amd64 go test -c -o kni.test ./builtin/kni
//	sudo KNI_REAL_NFT=1 unshare -n ./kni.test -test.run RealNFT -test.v
func TestRealNFTTakesTheRules(t *testing.T) {
	if os.Getenv("KNI_REAL_NFT") != "1" {
		t.Skip("KNI_REAL_NFT=1 runs nft -c on the generated rules (Linux, CAP_NET_ADMIN)")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Fatal("no nft")
	}
	cases := map[string]Host{}
	for seed := 0; seed < 60; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		base, h6 := v6Cluster(r)
		cases["v4-"+strconv.Itoa(seed)] = base
		cases["v6-"+strconv.Itoa(seed)] = h6
	}
	kept := web(v1.SiloSpec{Ports: []v1.SiloPort{{Name: "https", Port: 8443}, {Name: "dns", Port: 5353, Protocol: "UDP"}}, Services: []v1.SiloService{
		{Name: "api6", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "edge6"}, Ports: []v1.ServicePort{{Port: "https", As: 443, Sources: []string{"2001:db8:c::/48", "192.0.2.0/24"}}}},
		{Name: "pub", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: v1.NetworkExternal}, Ports: []v1.ServicePort{{Port: "dns"}}},
	}})
	kept.Addrs = map[string]netip.Addr{"api6": a("2001:db8:e::30")}
	kept.EgressIPv6 = a("2001:db8:e::30")
	kept.Egress = []v1.ParsedEgress{{Prefix: netip.MustParsePrefix("::/0"), Protocols: []string{"tcp", "udp"}, Ports: []v1.PortRange{{From: 443, To: 443}, {From: 8000, To: 8100}}}}
	h := host6(kept)
	h.OwnIPs = []netip.Addr{a("2001:db8:e::30"), a("198.51.100.30")}
	cases["kept6"] = h
	leased := web(opens(5432, v1.ServicePort{}, v1.NetworkExternal, v1.NetworkInternal))
	leased.Leased, leased.Closed = []string{"web"}, []string{"web"}
	cases["lease-cut6"] = host6(leased)
	bad := web(opens(443, v1.ServicePort{Sources: []string{"::ffff:192.0.2.7", "fe80::1%eth0", "2001:db8:c::/48"}}, v1.NetworkExternal))
	bad.EgressIPv6 = a("198.51.100.30")
	bad.Egress = []v1.ParsedEgress{{Prefix: netip.MustParsePrefix("::ffff:10.62.0.0/112"), Protocols: []string{"tcp"}}}
	hb := host6(bad, Silo{Key: "dev/out", IP: a("10.64.2.3"), IP6: a("fd00:aa:bb:9::3"), Tap: "kvt03"})
	hb.InternalIPv6, hb.ExternalIPv6 = a("fe80::5"), a("198.51.100.10")
	cases["invalid6"] = hb
	dir := t.TempDir()
	for name, h := range cases {
		path := filepath.Join(dir, name+".nft")
		if err := os.WriteFile(path, []byte(Rules(h)), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("nft", "-c", "-f", path).CombinedOutput(); err != nil {
			t.Errorf("%s: nft -c refused it: %v\n%s", name, err, out)
		}
	}
	t.Logf("nft -c took %d rulesets", len(cases))
}
