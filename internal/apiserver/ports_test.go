package apiserver

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// apiBlue is the design's api-blue silo (design §7.0) in networking v2: four declared ports, one
// way in per service.
func apiBlue() v1.SiloSpec {
	return v1.SiloSpec{
		Ports: []v1.SiloPort{{Name: "http", Port: 8080}, {Name: "https", Port: 8443}, {Name: "metrics", Port: 9090}, {Name: "debug", Port: 9229}},
		Services: []v1.SiloService{
			{Name: "api", Ports: []v1.ServicePort{{Port: "http", AllowFrom: []string{"nginx-public", "billing/worker"}}}},
			{Name: "api-public", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "https", As: 443}}},
			{Name: "api-ops", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: v1.NetworkInternal}, Ports: []v1.ServicePort{
				{Port: "metrics", Sources: []string{"10.0.0.0/24"}},
				{Port: "debug", Lease: &v1.PortLease{Max: "2h"}},
			}},
		},
	}
}

// expect runs the checks and wants an error containing want ("" for none).
func expect(t *testing.T, errs []string, want string) {
	t.Helper()
	if want == "" {
		if len(errs) > 0 {
			t.Fatalf("want no errors, got %q", errs)
		}
		return
	}
	for _, e := range errs {
		if strings.Contains(e, want) {
			return
		}
	}
	t.Fatalf("want an error with %q, got %q", want, errs)
}

func TestCheckPorts(t *testing.T) {
	lb := func(s *v1.SiloSpec) *v1.SiloService {
		s.Services = append(s.Services, v1.SiloService{Name: "shop", Type: v1.ServiceLoadBalancer,
			LoadBalancer: &v1.LoadBalancerSpec{Provider: "linode"}, Ports: []v1.ServicePort{{Port: "https", As: 443, Sources: []string{"0.0.0.0/0"}}}})
		return &s.Services[len(s.Services)-1]
	}
	for name, tc := range map[string]struct {
		edit  func(*v1.SiloSpec)
		inSet bool
		want  string // a substring of one error; "" means no errors
	}{
		"api-blue":                       {edit: func(*v1.SiloSpec) {}},
		"no service, no ports":           {edit: func(s *v1.SiloSpec) { s.Services = nil }},
		"a load balancer":                {edit: func(s *v1.SiloSpec) { lb(s) }},
		"a port in several services":     {edit: func(s *v1.SiloSpec) { s.Services[0].Ports = append(s.Services[0].Ports, v1.ServicePort{Port: "https"}) }},
		"hostPort on the worker's IP":    {edit: func(s *v1.SiloSpec) { s.Services[1].HostPort = &v1.HostPortSource{Worker: v1.NetworkExternal} }},
		"hostPort on an IP":              {edit: func(s *v1.SiloSpec) { s.Services[1].HostPort = &v1.HostPortSource{IP: "api-edge"} }},
		"own in a SiloSet's instance":    {edit: func(s *v1.SiloSpec) { s.Services[1].HostPort = &v1.HostPortSource{Own: true} }, inSet: true},
		"a load balancer's kept IP":      {edit: func(s *v1.SiloSpec) { lb(s).LoadBalancer.IP = "edge" }},
		"annotations on a load balancer": {edit: func(s *v1.SiloSpec) { lb(s).Annotations = map[string]string{"linode.kevaso.com/nodebalancer": "edge"} }},

		// One way in per service.
		"own outside a SiloSet": {edit: func(s *v1.SiloSpec) { s.Services[1].HostPort = &v1.HostPortSource{Own: true} },
			want: "own is a SiloSet instance's own IPSet member: a single silo names its address with hostPort.ip"},
		"two ways in one hostPort": {edit: func(s *v1.SiloSpec) { s.Services[1].HostPort = &v1.HostPortSource{Worker: "external", IP: "edge"} },
			want: "exactly one of worker, ip and own (two ways in inside one service)"},
		"an empty hostPort": {edit: func(s *v1.SiloSpec) { s.Services[1].HostPort = &v1.HostPortSource{} },
			want: "or leave hostPort out for { worker: external }"},
		"hostPort on a LoadBalancer": {edit: func(s *v1.SiloSpec) { lb(s).HostPort = &v1.HostPortSource{Worker: "external"} },
			want: "hostPort goes with type: HostPort; this one is LoadBalancer (two ways in"},
		"loadBalancer on a HostPort": {edit: func(s *v1.SiloSpec) { s.Services[1].LoadBalancer = &v1.LoadBalancerSpec{Provider: "linode"} },
			want: "loadBalancer goes with type: LoadBalancer; this one is HostPort"},
		"hostPort on an Internal service": {edit: func(s *v1.SiloSpec) { s.Services[0].HostPort = &v1.HostPortSource{Worker: "external"} },
			want: "hostPort goes with type: HostPort; this one is Internal"},
		"a LoadBalancer without a provider": {edit: func(s *v1.SiloSpec) { lb(s).LoadBalancer = nil },
			want: "type LoadBalancer needs loadBalancer.provider"},
		"an unknown type":       {edit: func(s *v1.SiloSpec) { s.Services[0].Type = "NodePort" }, want: `type "NodePort": Internal`},
		"a bad worker network":  {edit: func(s *v1.SiloSpec) { s.Services[1].HostPort = &v1.HostPortSource{Worker: "public"} }, want: `hostPort.worker "public": external or internal`},
		"a kind/name reference": {edit: func(s *v1.SiloSpec) { s.Services[1].HostPort = &v1.HostPortSource{IP: "ip/edge"} }, want: "no kind/ prefix"},
		"a bad provider":        {edit: func(s *v1.SiloSpec) { lb(s).LoadBalancer.Provider = "Linode" }, want: `loadBalancer.provider "Linode"`},

		// Names.
		"two unnamed services": {edit: func(s *v1.SiloSpec) { s.Services[1].Name, s.Services[2].Name = "", "" },
			want: "are both named api-blue (an unnamed service takes the silo's name)"},
		"a service named like an unnamed one": {edit: func(s *v1.SiloSpec) { s.Services[1].Name, s.Services[2].Name = "api-blue", "" },
			want: "both named api-blue"},
		"a bad service name": {edit: func(s *v1.SiloSpec) { s.Services[0].Name = "API" }, want: `name "API"`},
		"a service with no ports": {edit: func(s *v1.SiloSpec) { s.Services[0].Ports = nil },
			want: "no ports: a service opens at least one declared port"},

		// Ports.
		"undeclared service port": {edit: func(s *v1.SiloSpec) { s.Services[0].Ports[0].Port = "grpc" }, want: `"grpc" isn't a declared port`},
		"a port twice in one service": {edit: func(s *v1.SiloSpec) {
			s.Services[0].Ports = append(s.Services[0].Ports, v1.ServicePort{Port: "http", AllowFrom: []string{"other"}})
		}, want: "listed twice in one service"},
		"CIDR in allowFrom":   {edit: func(s *v1.SiloSpec) { s.Services[0].Ports[0].AllowFrom = []string{"10.0.0.0/8"} }, want: "ranges go in sources"},
		"allowFrom a/b/c":     {edit: func(s *v1.SiloSpec) { s.Services[0].Ports[0].AllowFrom = []string{"a/b/c"} }, want: "NAME or NAMESPACE/NAME"},
		"as on Internal":      {edit: func(s *v1.SiloSpec) { s.Services[0].Ports[0].As = 80 }, want: "as: only on a HostPort or LoadBalancer service"},
		"sources on Internal": {edit: func(s *v1.SiloSpec) { s.Services[0].Ports[0].Sources = []string{"10.0.0.0/8"} }, want: "sources: only on a HostPort or LoadBalancer service"},
		"a lease on a balancer": {edit: func(s *v1.SiloSpec) { lb(s).Ports[0].Lease = &v1.PortLease{Max: "1h"} },
			want: "leases are on HostPort services only"},
		"a lease on Internal": {edit: func(s *v1.SiloSpec) { s.Services[0].Ports[0].Lease = &v1.PortLease{Max: "1h"} },
			want: "leases are on HostPort services only"},
		"bad source":                              {edit: func(s *v1.SiloSpec) { s.Services[2].Ports[0].Sources = []string{"10.0.0.0/33"} }, want: "isn't an address or CIDR"},
		"as out of range":                         {edit: func(s *v1.SiloSpec) { s.Services[1].Ports[0].As = 70000 }, want: "70000 isn't from 1 to 65535"},
		"a reserved host port":                    {edit: func(s *v1.SiloSpec) { s.Services[1].Ports[0].As = 22 }, want: "22 is the SSH port"},
		"a reserved number on a balancer is fine": {edit: func(s *v1.SiloSpec) { lb(s).Ports[0].As = 22 }},
		"one number twice on one address": {edit: func(s *v1.SiloSpec) {
			s.Services[2].Ports[0].As = 9229 // metrics on internal 9229, which debug holds
		}, want: "9229/TCP on worker: internal is api-ops metrics's already"},
		"one number twice across services on one address": {edit: func(s *v1.SiloSpec) {
			s.Services = append(s.Services, v1.SiloService{Name: "other", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "http", As: 443}}})
		}, want: "443/TCP on worker: external is api-public https's already"},
		"one number on two addresses": {edit: func(s *v1.SiloSpec) { s.Services[2].HostPort, s.Services[2].Ports[1].As = nil, 9999 }},

		// Declared ports.
		"port declared twice": {edit: func(s *v1.SiloSpec) { s.Ports[1].Name = "http" }, want: "http is declared twice"},
		"same number twice":   {edit: func(s *v1.SiloSpec) { s.Ports[1].Port = 8080 }, want: "are both 8080/TCP"},
		"same number, other protocol": {edit: func(s *v1.SiloSpec) {
			s.Ports[1].Port, s.Ports[1].Protocol = 8080, "UDP"
		}},
		"port out of range": {edit: func(s *v1.SiloSpec) { s.Ports[0].Port = 70000 }, want: "isn't from 1 to 65535"},
		"bad protocol":      {edit: func(s *v1.SiloSpec) { s.Ports[0].Protocol = "SCTP" }, want: `protocol "SCTP"`},
		"bad port name":     {edit: func(s *v1.SiloSpec) { s.Ports[0].Name = "HTTP" }, want: "a port needs a name"},

		// The address out.
		"egress from an IP":   {edit: func(s *v1.SiloSpec) { s.Network.Egress.Source = &v1.EgressSource{IP: "mail"} }},
		"egress own in a set": {edit: func(s *v1.SiloSpec) { s.Network.Egress.Source = &v1.EgressSource{Own: true} }, inSet: true},
		"egress own outside a set": {edit: func(s *v1.SiloSpec) { s.Network.Egress.Source = &v1.EgressSource{Own: true} },
			want: "egress.source.own is a SiloSet instance's own IPSet member"},
		"egress with both": {edit: func(s *v1.SiloSpec) { s.Network.Egress.Source = &v1.EgressSource{IP: "mail", Own: true} },
			want: "exactly one of ip (an IP's name) and own: true"},
		"egress with neither": {edit: func(s *v1.SiloSpec) { s.Network.Egress.Source = &v1.EgressSource{} },
			want: "leave it out to send from the worker's own IP"},
	} {
		t.Run(name, func(t *testing.T) {
			spec := apiBlue()
			tc.edit(&spec)
			expect(t, checkPorts(spec, "api-blue", tc.inSet), tc.want)
		})
	}
}

func TestCheckTemplate(t *testing.T) {
	set := func(edit func(*v1.SiloSet)) *v1.SiloSet {
		s := &v1.SiloSet{}
		s.Name = "edge"
		s.Spec.Instances = 2
		s.Spec.Template.SiloSpec = apiBlue()
		edit(s)
		return s
	}
	for name, tc := range map[string]struct {
		edit func(*v1.SiloSet)
		want string
	}{
		"no addresses": {func(*v1.SiloSet) {}, ""},
		"own with ips": {func(s *v1.SiloSet) {
			s.Spec.IPs = "edge-ips"
			s.Spec.Template.Services[1].HostPort = &v1.HostPortSource{Own: true}
		}, ""},
		"egress own with ips": {func(s *v1.SiloSet) {
			s.Spec.IPs = "edge-ips"
			s.Spec.Template.Network.Egress.Source = &v1.EgressSource{Own: true}
		}, ""},
		"own without ips": {func(s *v1.SiloSet) { s.Spec.Template.Services[1].HostPort = &v1.HostPortSource{Own: true} },
			"the template says own, so the set needs ips: SETNAME"},
		"ips without own": {func(s *v1.SiloSet) { s.Spec.IPs = "edge-ips" }, "spec.ips edge-ips is only used with own"},
		"an ip in the template": {func(s *v1.SiloSet) { s.Spec.Template.Services[1].HostPort = &v1.HostPortSource{IP: "edge"} },
			"one IP can't serve many instances (even with one instance): use own: true"},
		"an ip with one instance": {func(s *v1.SiloSet) {
			s.Spec.Instances = 1
			s.Spec.Template.Services[1].HostPort = &v1.HostPortSource{IP: "edge"}
		}, "even with one instance"},
		"a balancer's ip in the template": {func(s *v1.SiloSet) {
			s.Spec.Template.Services = append(s.Spec.Template.Services, v1.SiloService{Name: "shop", Type: v1.ServiceLoadBalancer,
				LoadBalancer: &v1.LoadBalancerSpec{Provider: "linode", IP: "edge"}, Ports: []v1.ServicePort{{Port: "https"}}})
		}, "template.services[3].loadBalancer.ip names IP edge"},
		"egress ip in the template": {func(s *v1.SiloSet) { s.Spec.Template.Network.Egress.Source = &v1.EgressSource{IP: "mail"} },
			"template.network.egress.source.ip names IP mail"},
	} {
		t.Run(name, func(t *testing.T) { expect(t, checkTemplate(set(tc.edit)), tc.want) })
	}
}

func TestCheckService(t *testing.T) {
	svc := func(edit func(*v1.ServiceSpec)) *v1.Service {
		s := &v1.Service{}
		s.Name = "rpc"
		s.Spec = v1.ServiceSpec{Selector: map[string]string{"app": "rpc"}, Ports: []v1.ServicePortSpec{{Name: "rpc", Port: 8545}}}
		edit(&s.Spec)
		return s
	}
	for name, tc := range map[string]struct {
		edit func(*v1.ServiceSpec)
		want string
	}{
		"Internal by default": {func(*v1.ServiceSpec) {}, ""},
		"Internal":            {func(s *v1.ServiceSpec) { s.Type = v1.ServiceInternal }, ""},
		"LoadBalancer": {func(s *v1.ServiceSpec) {
			s.Type, s.LoadBalancer = v1.ServiceLoadBalancer, &v1.LoadBalancerSpec{Provider: "linode"}
		}, ""},
		"LoadBalancer with a kept IP": {func(s *v1.ServiceSpec) {
			s.Type, s.LoadBalancer = v1.ServiceLoadBalancer, &v1.LoadBalancerSpec{Provider: "azure", IP: "front"}
		}, ""},
		"HostPort":                      {func(s *v1.ServiceSpec) { s.Type = v1.ServiceHostPort }, "a Service of several can't be one"},
		"the old ClusterIP":             {func(s *v1.ServiceSpec) { s.Type = "ClusterIP" }, `type "ClusterIP": Internal`},
		"LoadBalancer with no provider": {func(s *v1.ServiceSpec) { s.Type = v1.ServiceLoadBalancer }, "needs loadBalancer.provider"},
		"loadBalancer on Internal": {func(s *v1.ServiceSpec) { s.LoadBalancer = &v1.LoadBalancerSpec{Provider: "linode"} },
			"loadBalancer goes with type: LoadBalancer"},
		"a kind/name ip": {func(s *v1.ServiceSpec) {
			s.Type, s.LoadBalancer = v1.ServiceLoadBalancer, &v1.LoadBalancerSpec{Provider: "linode", IP: "ip/front"}
		}, "no kind/ prefix"},
	} {
		t.Run(name, func(t *testing.T) { expect(t, checkService(svc(tc.edit)), tc.want) })
	}
}
