package kvo

import (
	"bytes"
	"strings"
	"testing"
	"text/tabwriter"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// A declared port that two services open (an Internal one for other silos, a HostPort one from
// outside) is reachable both ways: describe shows a row per service, each with its own way in,
// sources and the address the status gives it. It showed only the first service's row, so the
// HostPort's address and sources read as "-".
func TestDescribePortOpenedByTwoServices(t *testing.T) {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "dev", Namespace: "ai"}}
	s.Spec.Ports = []v1.SiloPort{{Name: "api", Port: 8000}, {Name: "debug", Port: 9000}}
	s.Spec.Services = []v1.SiloService{
		{Name: "api", Ports: []v1.ServicePort{{Port: "api", AllowFrom: []string{"app"}}}},
		{Name: "api-public", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: v1.NetworkInternal},
			Ports: []v1.ServicePort{{Port: "api", As: 443, Sources: []string{"198.51.100.7/32"}}}},
	}
	s.Status.SiloIP = "10.64.3.2"
	s.Status.Service.Ports = []v1.ServicePortStatus{
		{Port: "api", Mesh: "10.64.3.2:8000"},
		{Port: "api", Mesh: "10.64.3.2:8000", Internal: "192.0.2.10:443"},
	}
	var b bytes.Buffer
	tw := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	writeSiloPorts(tw, s)
	_ = tw.Flush()
	rows := map[string][]string{}
	for _, l := range strings.Split(b.String(), "\n") {
		f := strings.Fields(l)
		if len(f) > 0 {
			rows[strings.Join(f[:min(2, len(f))], " ")] = f
		}
	}
	pub := rows["api (api-public)"]
	if pub == nil {
		t.Fatalf("no row for the HostPort service:\n%s", b.String())
	}
	if !strings.Contains(strings.Join(pub, " "), "192.0.2.10:443") || pub[len(pub)-1] != "198.51.100.7/32" {
		t.Errorf("HostPort row lacks its address or sources: %q\n%s", pub, b.String())
	}
	in := rows["api (api)"]
	if in == nil || !strings.Contains(strings.Join(in, " "), "app") || strings.Contains(strings.Join(in, " "), "192.0.2.10") {
		t.Errorf("Internal row wrong: %q\n%s", in, b.String())
	}
	if strings.Contains(strings.Join(pub, " "), "no silo allowed") {
		t.Errorf("app may connect through the Internal service, yet the HostPort row says no silo is allowed: %q", pub)
	}
	if !strings.Contains(b.String(), "not opened: reachable nowhere") {
		t.Errorf("the unopened port lost its row:\n%s", b.String())
	}
}
