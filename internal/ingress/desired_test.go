package ingress

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kic/nginx"
	"kevaso.com/core/sdk/kic/kictest"
)

func class() *v1.IngressClass {
	return &v1.IngressClass{ObjectMeta: meta.ObjectMeta{Name: "public"}, Spec: v1.IngressClassSpec{Controller: v1.IngressController{Driver: "nginx", Silo: "edge", Namespace: "kevaso-system"}}}
}

func ing(ns, name string, hosts []string, rules ...v1.IngressRule) *v1.Ingress {
	return &v1.Ingress{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns}, Spec: v1.IngressSpec{IngressClass: "public", Hosts: hosts, Rules: rules}}
}

func rule(path, service string) v1.IngressRule {
	return v1.IngressRule{Path: path, Service: v1.IngressTarget{Name: service, Port: "http"}}
}

func inputs(ings ...*v1.Ingress) Inputs {
	var silos []*v1.Silo
	// Each silo's service is named after it, except api-blue's, which is api.
	for i, n := range []string{"payments/api-blue", "payments/ws", "shop/web", "shop/down"} {
		ns, name, _ := strings.Cut(n, "/")
		s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns}, Spec: v1.SiloSpec{
			Ports:   []v1.SiloPort{{Name: "http", Port: 8000 + i}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "http"}}}},
			Status: v1.SiloStatus{Phase: "Running", SiloIP: "10.64.0." + string(rune('1'+i))}}
		if name == "api-blue" {
			s.Spec.Service.Name = "api"
		}
		if name == "down" {
			s.Status.Phase, s.Status.SiloIP = "Stopped", ""
		}
		silos = append(silos, s)
	}
	// A standalone Service in front of silos: its cluster IP, while it has an endpoint.
	front := &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "front", Namespace: "shop"},
		Spec:   v1.ServiceSpec{Ports: []v1.ServicePortSpec{{Name: "http", Port: 80}}},
		Status: v1.ServiceStatus{ClusterIP: "10.65.0.9", Endpoints: []v1.ServiceEndpoint{{Silo: "web", SiloIP: "10.64.0.3"}}}}
	return Inputs{Class: class(), Driver: nginx.Driver{}, Ingresses: ings,
		Silos: silos, Services: []*v1.Service{front},
		Bundle: func(ns, secret string) []byte {
			return map[string][]byte{"payments/api-tls": []byte(kictest.Chain + kictest.Key)}[ns+"/"+secret]
		},
		Challenges: map[string]string{"tok-b": "tok-b.k", "tok-a": "tok-a.k"}}
}

func TestDesire(t *testing.T) {
	api := ing("payments", "api", []string{"API.example.com."}, rule("/", "api"), rule("/ws", "ws"))
	api.Annotations = map[string]string{"nginx/proxy-body-size": "10m", "caddy/dial-timeout": "1s"}
	shop := ing("shop", "web", []string{"shop.example.com"}, rule("", "web"), rule("/down", "down"), rule("/front", "front"))
	shop.Spec.TLS.None = true
	steal := ing("zoo", "steal", []string{"api.example.com"}, rule("/", "api")) // later by name: api.example.com / stays payments/api's
	other := ing("x", "other", []string{"o.example.com"}, rule("/", "api"))
	other.Spec.IngressClass = "private"
	gone := ing("x", "gone", []string{"g.example.com"}, rule("/", "api"))
	now := time.Now()
	gone.DeletionTimestamp = &now
	d := Desire(inputs(steal, shop, api, other, gone))
	if d.Problem != "" || len(d.Refused) != 0 {
		t.Fatalf("problem %q, refused %v", d.Problem, d.Refused)
	}
	got := []string{}
	for _, r := range d.State.Routes {
		got = append(got, r.Ingress+" "+r.Host+r.Path+" → "+r.Backend.Address)
	}
	want := []string{"payments/api api.example.com/ws → 10.64.0.2", "payments/api api.example.com/ → 10.64.0.1",
		"shop/web shop.example.com/front → 10.65.0.9", "shop/web shop.example.com/ → 10.64.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("routes %v", got)
	}
	if r := d.State.Routes[0]; !r.TLS || r.Backend.Port != 8001 || !reflect.DeepEqual(r.Annotations, map[string]string{"proxy-body-size": "10m"}) {
		t.Fatalf("route %+v", r)
	}
	if r := d.State.Routes[2]; r.Backend.Port != 80 {
		t.Fatalf("a Service's backend is its own port: %+v", r)
	}
	if d.State.Routes[3].TLS {
		t.Fatal("tls.none routes are plain")
	}
	if len(d.State.Certificates) != 1 || d.State.Certificates[0].Name != "payments/api-tls" || d.State.Certificates[0].Hosts[0] != "api.example.com" ||
		string(d.State.Certificates[0].Chain) != kictest.Chain || string(d.State.Certificates[0].Key) != kictest.Key {
		t.Fatalf("certificates %+v", d.State.Certificates)
	}
	if len(d.State.Challenges) != 2 || d.State.Challenges[0].Token != "tok-a" {
		t.Fatalf("challenges %+v", d.State.Challenges)
	}
	if !reflect.DeepEqual(Desire(inputs(api, steal, shop, gone, other)), d) {
		t.Fatal("the order of the Ingresses changed the result")
	}
	// Where probes plug in: a silo that isn't routed to has no route.
	in := inputs(api)
	in.Routed = func(s *v1.Silo) bool { return s.Name != "ws" }
	if d := Desire(in); len(d.State.Routes) != 1 || d.State.Routes[0].Path != "/" {
		t.Fatalf("routed: %+v", d.State.Routes)
	}
}

func TestDesireRefuses(t *testing.T) {
	bad := ing("payments", "api", []string{"api.example.com"}, rule("/", "api"))
	bad.Annotations = map[string]string{"nginx/proxy-body-size": "huge", "nginx/no-such": "x"}
	d := Desire(inputs(bad, ing("shop", "web", []string{"shop.example.com"}, rule("/", "web"))))
	if why := d.Refused["payments/api"]; !strings.Contains(why, "nginx/no-such") || !strings.Contains(why, "proxy-body-size") {
		t.Fatalf("refused %v", d.Refused)
	}
	if len(d.State.Routes) != 1 || d.State.Routes[0].Ingress != "shop/web" {
		t.Fatalf("routes %+v", d.State.Routes)
	}
	in := inputs()
	in.Driver = nil
	if d := Desire(in); !strings.Contains(d.Problem, "nginx") {
		t.Fatalf("no driver: %q", d.Problem)
	}
	in = inputs()
	in.Class.Spec.Controller.Options = map[string]string{"workers": "8"}
	if d := Desire(in); !strings.Contains(d.Problem, "unknown option workers") {
		t.Fatalf("bad option: %q", d.Problem)
	}
	evil := ing("payments", "evil", []string{"a.example.com"}, rule("/x;}", "api"))
	if d := Desire(inputs(evil)); d.Refused["payments/evil"] == "" {
		t.Fatal("a path that would paste config in")
	}
}

func TestRefusedAndHostWrite(t *testing.T) {
	c := class()
	bad := ing("payments", "api", []string{"api.example.com"}, rule("/", "api"))
	bad.Annotations = map[string]string{"nginx/nope": "1"}
	if reason, _ := Refused(builtins(), c, bad); reason != "Refused" {
		t.Fatalf("reason %q", reason)
	}
	ok := ing("payments", "ok", []string{"ok.example.com"}, rule("/", "api"))
	if reason, _ := Refused(builtins(), c, ok); reason != "" {
		t.Fatalf("reason %q", reason)
	}
	c.Status.Controllers = []v1.IngressControllerStatus{{Silo: "edge", Host: "hv1", Rejected: "bad cert", Blamed: []string{"payments/ok"}}}
	if reason, msg := Refused(builtins(), c, ok); reason != "Rejected" || !strings.Contains(msg, "bad cert") {
		t.Fatalf("reason %q %q", reason, msg)
	}
	old := v1.IngressClassStatus{Controllers: []v1.IngressControllerStatus{{Silo: "edge-0", Host: "hv1"}, {Silo: "edge-1", Host: "hv2"}}}
	mine := v1.IngressClassStatus{Controllers: []v1.IngressControllerStatus{{Silo: "edge-0", Host: "hv1", Applied: "abc"}, {Silo: "edge-1", Host: "hv2"}}}
	if err := HostWrite(old, mine, "hv1"); err != nil {
		t.Fatal(err)
	}
	theirs := v1.IngressClassStatus{Controllers: []v1.IngressControllerStatus{{Silo: "edge-0", Host: "hv1"}, {Silo: "edge-1", Host: "hv2", Applied: "x"}}}
	if err := HostWrite(old, theirs, "hv1"); err == nil {
		t.Fatal("hv1 wrote hv2's entry")
	}
	if err := HostWrite(old, v1.IngressClassStatus{Controllers: old.Controllers[:1]}, "hv1"); err == nil {
		t.Fatal("hv1 removed hv2's entry")
	}
}

func TestSplitBundle(t *testing.T) {
	if c, k := SplitBundle([]byte(kictest.Key + kictest.Chain + kictest.Chain)); string(c) != kictest.Chain+kictest.Chain || string(k) != kictest.Key {
		t.Fatalf("chain %q key %q", c, k)
	}
	if c, k := SplitBundle([]byte(kictest.Chain)); c != nil || k != nil {
		t.Fatal("no key: nothing")
	}
}
