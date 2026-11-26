package v1

import (
	"encoding/json"
	"slices"
	"testing"

	"kevaso.com/core/api/meta"
)

func v2Silo() *Silo {
	return &Silo{ObjectMeta: meta.ObjectMeta{Name: "mail", Namespace: "m"}, Spec: SiloSpec{
		Ports: []SiloPort{{Name: "smtp", Port: 25}, {Name: "imaps", Port: 993}, {Name: "metrics", Port: 9100}},
		Services: []SiloService{
			{Type: ServiceHostPort, HostPort: &HostPortSource{IP: "mail"}, Ports: []ServicePort{{Port: "smtp"}, {Port: "imaps", As: 9993}}},
			{Name: "web", Type: ServiceHostPort, Ports: []ServicePort{{Port: "imaps"}}},
			{Name: "shop", Type: ServiceLoadBalancer, LoadBalancer: &LoadBalancerSpec{Provider: "azure", IP: "front"}, Ports: []ServicePort{{Port: "imaps", As: 443}}},
			{Name: "metrics", Ports: []ServicePort{{Port: "metrics", AllowFrom: []string{"monitoring/prometheus"}}}},
		},
		Network: SiloNetwork{Egress: Egress{Source: &EgressSource{IP: "mail"}}},
	}}
}

func TestServiceTypesAndWays(t *testing.T) {
	sv := SiloService{}
	if sv.TypeOrDefault() != ServiceInternal || sv.Way() != (HostPortSource{}) {
		t.Fatalf("an empty service: %s %+v", sv.TypeOrDefault(), sv.Way())
	}
	sv.Type = ServiceHostPort
	if sv.Way() != (HostPortSource{Worker: NetworkExternal}) {
		t.Fatalf("a HostPort with no hostPort is { worker: external }: %+v", sv.Way())
	}
	sv.HostPort = &HostPortSource{Own: true}
	if sv.Way().String() != "own" || sv.Way().Ways() != 1 {
		t.Fatalf("own: %q", sv.Way().String())
	}
	if (HostPortSource{Worker: "external", IP: "x"}).Ways() != 2 || (EgressSource{IP: "a", Own: true}).Ways() != 2 {
		t.Fatal("two ways counted as one")
	}
}

func TestOpenPortsAcrossServices(t *testing.T) {
	s := v2Silo()
	open := s.Spec.OpenIn(s.Name)
	if len(open) != 5 {
		t.Fatalf("%d open ports, want 5 (imaps is in three services)", len(open))
	}
	first := open[0]
	if first.Service != "mail" || first.Type != ServiceHostPort || first.Way.IP != "mail" || len(first.HostPort) != 0 {
		t.Fatalf("smtp: %+v", first)
	}
	if web := open[2]; web.Service != "web" || !web.On(NetworkExternal) || web.On(NetworkInternal) || web.HostNumber() != 993 {
		t.Fatalf("web's imaps: %+v", web)
	}
	if lb := open[3]; !lb.LoadBalancer || !lb.Outside() || lb.HostNumber() != 443 {
		t.Fatalf("shop's imaps: %+v", lb)
	}
	if m := open[4]; m.Outside() || m.Type != ServiceInternal {
		t.Fatalf("metrics: %+v", m)
	}
	if !s.Spec.LoadBalanced() || !s.Spec.OnHost() || len(s.Spec.Balancers()) != 1 {
		t.Fatal("LoadBalanced, OnHost or Balancers wrong")
	}
	if got := ServiceNames(s); !slices.Equal(got, []string{"mail", "web", "shop", "metrics"}) {
		t.Fatalf("names %v", got)
	}
	if !AllowedFrom(s, "metrics", "monitoring/prometheus") || AllowedFrom(s, "smtp", "monitoring/prometheus") {
		t.Fatal("allowFrom read from the wrong service")
	}
}

func TestNamedIPsAndPorts(t *testing.T) {
	s := v2Silo()
	if got := SiloIPs(s); !slices.Equal(got, []string{"mail", "front"}) {
		t.Fatalf("SiloIPs %v (each once, services first)", got)
	}
	if n := s.Spec.NamedIPs(); n[0].Field != "services[0].hostPort.ip" || n[1].Field != "services[2].loadBalancer.ip" {
		t.Fatalf("fields %+v", n)
	}
	if got := SiloPortsOn(s, "mail"); !slices.Equal(got, []string{"25/TCP", "9993/TCP"}) {
		t.Fatalf("ports on mail %v", got)
	}
	if got := SiloPortsOn(s, "front"); !slices.Equal(got, []string{"443/TCP"}) {
		t.Fatalf("ports on front %v", got)
	}
	if s.Spec.UsesOwn() {
		t.Fatal("no own, yet UsesOwn")
	}
	s.Spec.Network.Egress.Source = &EgressSource{Own: true}
	if !s.Spec.UsesOwn() {
		t.Fatal("egress own not seen")
	}
}

func TestInstancesNameTheirServices(t *testing.T) {
	set := &SiloSet{ObjectMeta: meta.ObjectMeta{Name: "edge", Namespace: "m"}, Spec: SiloSetSpec{Instances: 2, IPs: "edge-ips",
		Template: SiloTemplate{SiloSpec: SiloSpec{Ports: []SiloPort{{Name: "http", Port: 80}},
			Services: []SiloService{
				{Type: ServiceHostPort, HostPort: &HostPortSource{Own: true}, Ports: []ServicePort{{Port: "http"}}},
				{Name: "metrics", Ports: []ServicePort{{Port: "http"}}},
			}}}}}
	i1 := set.Instance(1, false)
	if got := ServiceNames(i1); !slices.Equal(got, []string{"edge-1", "edge-1-metrics"}) {
		t.Fatalf("instance 1's services %v", got)
	}
	i1.Spec.Services[0].HostPort.Own = false
	i1.Spec.Services[1].Ports[0].Port = "x"
	if !set.Spec.Template.Services[0].HostPort.Own || set.Spec.Template.Services[1].Name != "metrics" {
		t.Fatal("an instance shares its services with the template")
	}
	if set.Spec.Template.Services[1].Ports[0].Port != "http" {
		t.Fatal("an instance shares its service ports with the template")
	}
	if i1.Labels[LabelRevision] != set.Revision() {
		t.Fatal("an instance's revision isn't its set's")
	}
}

func TestIPStatusOneHolder(t *testing.T) {
	st := IPStatus{}
	if st.Holds("u1") || st.Holders() != "" {
		t.Fatal("nobody holds an empty status")
	}
	st.Holder = &IPHolder{Holder: "silo/mail", UID: "u1", Ports: []string{"25/TCP"}}
	if !st.Holds("u1") || st.Holds("u2") || st.Holds("") || st.Holders() != "silo/mail (25/TCP)" {
		t.Fatalf("holder: %v %q", st.Holds("u1"), st.Holders())
	}
}

func TestNewKindsRoundTrip(t *testing.T) {
	for _, obj := range []string{
		`{"apiVersion":"kevaso/v1","kind":"IP","metadata":{"name":"mail","namespace":"m"},"spec":{"type":"Host","hostAddress":"mail"}}`,
		`{"apiVersion":"kevaso/v1","kind":"IP","metadata":{"name":"edge","namespace":"m"},"spec":{"type":"Provider","provider":"linode","region":"us-ord"}}`,
		`{"apiVersion":"kevaso/v1","kind":"IPSet","metadata":{"name":"s","namespace":"m"},"spec":{"type":"Static","members":[{"ip":"a"},{"hostAddress":"b"}]}}`,
		`{"apiVersion":"kevaso/v1","kind":"IPSet","metadata":{"name":"d","namespace":"m"},"spec":{"type":"Dynamic","provider":"linode","region":"us-ord","max":3}}`,
		`{"apiVersion":"kevaso/v1","kind":"Host","metadata":{"name":"h"},"spec":{"externalIP":"203.0.113.10","components":{},"addresses":[{"name":"mail","kind":"external","address":"203.0.113.21"}]}}`,
		`{"apiVersion":"kevaso/v1","kind":"SiloSet","metadata":{"name":"e","namespace":"m"},"spec":{"instances":1,"ips":"s","template":{"runtime":"docker","services":[{"type":"HostPort","hostPort":{"own":true},"ports":[{"port":"w"}]}],"network":{"egress":{"source":{"own":true}}}}}}`,
		`{"apiVersion":"kevaso/v1","kind":"Service","metadata":{"name":"rpc","namespace":"m"},"spec":{"selector":{"a":"b"},"ports":[{"name":"rpc","port":1}],"type":"LoadBalancer","loadBalancer":{"provider":"linode"}}}`,
	} {
		o, k, err := DecodeStrict([]byte(obj))
		if err != nil {
			t.Fatalf("%s: %v", obj, err)
		}
		b, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := DecodeStrict(b); err != nil {
			t.Fatalf("%s again: %v", k.Kind, err)
		}
	}
	if k, ok := Lookup("ipsets"); !ok || k.Kind != "IPSet" || k.Scope != Namespaced {
		t.Fatalf("ipsets: %+v %v", k, ok)
	}
	if DynamicMemberName("edge", 2) != "edge-2" {
		t.Fatal("a Dynamic set's member names")
	}
}
