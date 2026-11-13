package apiserver

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// apiBlue is the design's api-blue silo (design §7.0): four declared ports, each opened its own way.
func apiBlue() v1.SiloSpec {
	return v1.SiloSpec{
		Ports: []v1.SiloPort{{Name: "http", Port: 8080}, {Name: "https", Port: 8443}, {Name: "metrics", Port: 9090}, {Name: "debug", Port: 9229}},
		Service: &v1.SiloService{Name: "api", Ports: []v1.ServicePort{
			{Port: "http", AllowFrom: []string{"nginx-public", "billing/worker"}},
			{Port: "https", HostPort: []string{"external"}, As: 443},
			{Port: "metrics", HostPort: []string{"internal"}, Sources: []string{"10.0.0.0/24"}},
			{Port: "debug", HostPort: []string{"internal"}, Lease: &v1.PortLease{Max: "2h"}},
		}},
	}
}

func TestCheckPorts(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*v1.SiloSpec)
		want string // a substring of one error; "" means no errors
	}{
		"api-blue": {func(*v1.SiloSpec) {}, ""},
		"a port on the load balancer": {func(s *v1.SiloSpec) {
			s.Service.Ports[1] = v1.ServicePort{Port: "https", LoadBalancer: true, As: 443, Sources: []string{"0.0.0.0/0"}}
			s.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: "linode-nodebalancer"}
		}, ""},
		"undeclared service port": {func(s *v1.SiloSpec) { s.Service.Ports[0].Port = "grpc" }, `"grpc" isn't a declared port`},
		"a port opened twice": {func(s *v1.SiloSpec) {
			s.Service.Ports = append(s.Service.Ports, v1.ServicePort{Port: "http", AllowFrom: []string{"other"}})
		}, "opened twice"},
		"CIDR in allowFrom":                   {func(s *v1.SiloSpec) { s.Service.Ports[0].AllowFrom = []string{"10.0.0.0/8"} }, "ranges go in sources"},
		"allowFrom a/b/c":                     {func(s *v1.SiloSpec) { s.Service.Ports[0].AllowFrom = []string{"a/b/c"} }, "NAME or NAMESPACE/NAME"},
		"bad hostPort word":                   {func(s *v1.SiloSpec) { s.Service.Ports[1].HostPort = []string{"public"} }, `hostPort: "public": internal or external`},
		"hostPort twice":                      {func(s *v1.SiloSpec) { s.Service.Ports[1].HostPort = []string{"external", "external"} }, "external twice"},
		"as without hostPort or loadBalancer": {func(s *v1.SiloSpec) { s.Service.Ports[0].As = 80 }, "as: only with hostPort or loadBalancer"},
		"sources without hostPort or loadBalancer": {func(s *v1.SiloSpec) { s.Service.Ports[0].Sources = []string{"10.0.0.0/8"} },
			"sources: only with hostPort or loadBalancer"},
		"bad source": {func(s *v1.SiloSpec) { s.Service.Ports[2].Sources = []string{"10.0.0.0/33"} }, "isn't an address or CIDR"},
		"same as-number on the same network twice": {func(s *v1.SiloSpec) {
			s.Service.Ports[2].As = 9229 // metrics on internal 9229, which debug holds
		}, "on the internal IP is"},
		"same as-number on different networks": {func(s *v1.SiloSpec) {
			s.Service.Ports[2].HostPort, s.Service.Ports[2].As = []string{"external"}, 9229
		}, ""},
		"loadBalancer without class": {func(s *v1.SiloSpec) { s.Service.Ports[1].LoadBalancer = true }, "needs service.loadBalancer.class"},
		"service.loadBalancer without any LB port": {func(s *v1.SiloSpec) {
			s.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: v1.LBIPPool}
		}, "no port says so"},
		"dedicated with ip": {func(s *v1.SiloSpec) {
			s.Service.Ports[1].LoadBalancer = true
			s.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: v1.LBIPPool, IP: "eth", Dedicated: true}
		}, "not with loadBalancer.ip"},
		"sameAsService without an outside port": {func(s *v1.SiloSpec) {
			s.Service.Ports = s.Service.Ports[:1]
			s.Network.Egress.Source = v1.EgressSameAsService
		}, "sameAsService needs a port on the host or a load balancer"},
		"sameAsService without a service": {func(s *v1.SiloSpec) {
			s.Service = nil
			s.Network.Egress.Source = v1.EgressSameAsService
		}, "sameAsService needs a service"},
		"sameAsService with a host port": {func(s *v1.SiloSpec) { s.Network.Egress.Source = v1.EgressSameAsService }, ""},
		"egress pool without an IP":      {func(s *v1.SiloSpec) { s.Network.Egress.Source = v1.EgressPool }, "pool needs egress.ip"},
		"port declared twice":            {func(s *v1.SiloSpec) { s.Ports[1].Name = "http" }, "http is declared twice"},
		"same number twice":              {func(s *v1.SiloSpec) { s.Ports[1].Port = 8080 }, "are both 8080/TCP"},
		"same number, other protocol": {func(s *v1.SiloSpec) {
			s.Ports[1].Port, s.Ports[1].Protocol = 8080, "UDP"
		}, ""},
		"port out of range":    {func(s *v1.SiloSpec) { s.Ports[0].Port = 70000 }, "isn't from 1 to 65535"},
		"bad protocol":         {func(s *v1.SiloSpec) { s.Ports[0].Protocol = "SCTP" }, `protocol "SCTP"`},
		"bad port name":        {func(s *v1.SiloSpec) { s.Ports[0].Name = "HTTP" }, "a port needs a name"},
		"bad service name":     {func(s *v1.SiloSpec) { s.Service.Name = "API" }, `service.name "API"`},
		"no service, no ports": {func(s *v1.SiloSpec) { s.Service = nil }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			spec := apiBlue()
			tc.edit(&spec)
			errs := checkPorts(spec)
			if tc.want == "" {
				if len(errs) > 0 {
					t.Fatalf("want no errors, got %q", errs)
				}
				return
			}
			for _, e := range errs {
				if strings.Contains(e, tc.want) {
					return
				}
			}
			t.Fatalf("want an error with %q, got %q", tc.want, errs)
		})
	}
}
