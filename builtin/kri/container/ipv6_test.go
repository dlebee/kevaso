package container

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// runIPv6 answers the namespace's `ip -6` commands: an address replace and a route replace are
// kept per pid; shows print them back like iproute2.
func (f *fake) runIPv6(a []string, out func(string)) (int, error) {
	pid := f.pid
	if f.v6 == nil {
		f.v6 = map[int][2]string{}
	}
	cur := f.v6[pid]
	line := strings.Join(a, " ")
	switch {
	case strings.Contains(line, "addr replace"):
		cur[0] = a[indexOf(a, "replace")+1]
	case strings.Contains(line, "route replace default via"):
		cur[1] = a[indexOf(a, "via")+1]
	case strings.Contains(line, "addr show"):
		if cur[0] != "" {
			out("2: eth0    inet6 " + cur[0] + " scope global nodad \\       valid_lft forever preferred_lft forever\n")
		}
	case strings.Contains(line, "route show default"):
		if cur[1] != "" {
			out("default via " + cur[1] + " dev eth0 metric 1024 pref medium\n")
		}
	}
	f.v6[pid] = cur
	return 0, nil
}

// spec6 is a silo's spec on a host with silo IPv6.
func spec6() kri.Spec {
	return kri.Spec{ID: silo, Image: "ubuntu-24.04", Subnet6: "fd12:3456:789a:3::/64", Gateway6: "fd12:3456:789a:3::1"}
}

func (f *fake) count(prefix string) int {
	n := 0
	for _, c := range f.cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// A spec with silo IPv6: the namespace gets the silo's IPv6 address (the IPv4 host part in the
// host's /64) and a default IPv6 route via the bridge, with router advertisements off before eth0
// is up; the state and Status carry the address.
func TestIPv6Wired(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	if err := r.Create(ctx, spec6()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"nsenter -t 100 -n ip link set kvp" + NamesFor(silo).Short + " name eth0",
		"nsenter -t 100 -n sysctl -q -w net.ipv6.conf.all.accept_ra=0",
		"nsenter -t 100 -n sysctl -q -w net.ipv6.conf.default.autoconf=0",
		"nsenter -t 100 -n sysctl -q -w net.ipv6.conf.eth0.accept_ra=0",
		"nsenter -t 100 -n sysctl -q -w net.ipv6.conf.eth0.autoconf=0",
		"nsenter -t 100 -n sysctl -q -w net.ipv6.conf.eth0.disable_ipv6=0",
		"nsenter -t 100 -n ip link set eth0 up",
		"nsenter -t 100 -n ip -6 addr replace fd12:3456:789a:3::2/64 dev eth0 nodad",
		"nsenter -t 100 -n ip -6 route replace default via fd12:3456:789a:3::1 dev eth0",
	}
	at := -1
	for _, w := range want {
		i := at + 1
		for ; i < len(f.cmds) && f.cmds[i] != w; i++ {
		}
		if i == len(f.cmds) {
			t.Fatalf("missing (or out of order) %q in:\n%s", w, strings.Join(f.cmds, "\n"))
		}
		at = i
	}
	s, _ := r.load(silo)
	if s.IP != "10.64.0.2" || s.IP6 != "fd12:3456:789a:3::2" || s.Gateway6 != "fd12:3456:789a:3::1" {
		t.Fatalf("state %+v", s)
	}
	var raw map[string]any
	if err := json.Unmarshal(f.files[NamesFor(silo).Dir+"/state.json"], &raw); err != nil || raw["ip6"] != "fd12:3456:789a:3::2" {
		t.Fatalf("state.json %s (%v): the worker reads ip6", f.files[NamesFor(silo).Dir+"/state.json"], err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.Status(ctx, silo); st.Address != "10.64.0.2" || st.Address6 != "fd12:3456:789a:3::2" {
		t.Fatalf("status %+v", st)
	}
	// Wired already: a second start changes nothing.
	if n := f.count("nsenter -t 100 -n ip -6 addr replace"); n != 1 {
		t.Fatalf("address given %d times", n)
	}
}

// A host without silo IPv6: not one IPv6 command, and nothing of it in the state or Status.
func TestNoIPv6Unchanged(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.cmds {
		if strings.Contains(c, "-6") || strings.Contains(c, "ipv6") {
			t.Errorf("an IPv6 command on a host without silo IPv6: %s", c)
		}
	}
	s, _ := r.load(silo)
	st, _ := r.Status(ctx, silo)
	if s.IP6 != "" || s.Gateway6 != "" || st.Address6 != "" || strings.Contains(string(f.files[NamesFor(silo).Dir+"/state.json"]), "ip6") {
		t.Fatalf("IPv6 %+v %+v", s, st)
	}
}

// A silo wired before its host had silo IPv6 gets it at its next Create (the agent's, which is
// done again on a silo that exists), without being wired over. A spec without IPv6 again takes
// it out of the state and Status (kni opens nothing for it then).
func TestIPv6AddedToAWiredSilo(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, spec6()); err != nil {
		t.Fatal(err)
	}
	if f.count("ip link add") != 1 {
		t.Fatal("wired over")
	}
	if got := f.v6[100]; got != [2]string{"fd12:3456:789a:3::2/64", "fd12:3456:789a:3::1"} {
		t.Fatalf("namespace %v", got)
	}
	if s, _ := r.load(silo); s.IP6 != "fd12:3456:789a:3::2" {
		t.Fatalf("state %+v", s)
	}
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.load(silo); s.IP6 != "" || s.Gateway6 != "" {
		t.Fatalf("state keeps %+v with no IPv6 in the spec", s)
	}
}

// The engines are told to make no IPv6 (or IPv4) firewall rules of their own.
func TestDockerMakesNoIPv6Rules(t *testing.T) {
	b, _ := DockerDaemonConfig([]byte(`{"ip6tables": true, "ipv6": true}`), false)
	for _, w := range []string{`"ip6tables": false`, `"iptables": false`, `"bridge": "none"`} {
		if !strings.Contains(string(b), w) {
			t.Errorf("daemon.json %s lacks %s", b, w)
		}
	}
}
