package names

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// The design's example (§7.0): api-blue in payments, service api, on ovh-1 (internal 10.0.0.5,
// external 51.38.10.20, mesh 10.63.0.2); https on the external IP, metrics on the internal one.
func view() View {
	ovh := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "ovh-1"}, Spec: v1.HostSpec{InternalIP: "10.0.0.5", ExternalIP: "51.38.10.20"}}
	ovh.Status.Network.MeshIP = "10.63.0.2"
	lan := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "lan-1"}, Spec: v1.HostSpec{InternalIP: "192.168.1.20"}}
	lan.Status.Network.MeshIP = "10.63.0.3"

	api := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "api-blue", Namespace: "payments"}}
	api.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 8080}, {Name: "https", Port: 8443}, {Name: "metrics", Port: 9090}}
	api.Spec.Service = &v1.SiloService{Name: "api", Ports: []v1.ServicePort{
		{Port: "http", AllowFrom: []string{"nginx-public"}},
		{Port: "https", HostPort: []string{"external"}, As: 443},
		{Port: "metrics", HostPort: []string{"internal"}},
	}}
	api.Status.Host, api.Status.SiloIP, api.Status.Phase = "ovh-1", "10.64.2.7", "Running"

	db := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "payments"}}
	db.Spec.Ports = []v1.SiloPort{{Name: "pg", Port: 5432}}
	db.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Port: "pg", AllowFrom: []string{"api-blue"}}}}
	db.Status.Host, db.Status.SiloIP = "lan-1", "10.64.3.4"

	// Held by routeWhen: ready, and not ready.
	slow := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "slow", Namespace: "payments"}}
	slow.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 80}}
	slow.Spec.Probes = &v1.Probes{Readiness: &v1.Probe{TCP: &v1.TCPProbe{Port: "http"}}}
	slow.Spec.Service = &v1.SiloService{RouteWhen: v1.RouteWhenReady, Ports: []v1.ServicePort{{Port: "http", HostPort: []string{"external"}}}}
	slow.Status.Host, slow.Status.SiloIP = "ovh-1", "10.64.2.9"

	// No service: no name.
	worker := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "worker", Namespace: "payments"}}
	worker.Status.Host, worker.Status.SiloIP = "ovh-1", "10.64.2.8"

	// A set's instances behind a Service.
	rpc0 := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "rpc-0", Namespace: "web3", Labels: map[string]string{"app": "rpc"}}}
	rpc0.Spec.Ports = []v1.SiloPort{{Name: "rpc", Port: 8545}}
	rpc0.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Port: "rpc", HostPort: []string{"internal"}}}}
	rpc0.Status.Host, rpc0.Status.SiloIP = "lan-1", "10.64.3.5"
	svc := &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "web3"}}
	svc.Status.ClusterIP = "10.65.0.1"
	svc.Status.Endpoints = []v1.ServiceEndpoint{{Silo: "rpc-0", Host: "lan-1", SiloIP: "10.64.3.5"}}

	return View{Silos: []*v1.Silo{api, db, slow, worker, rpc0}, Services: []*v1.Service{svc}, Hosts: []*v1.Host{ovh, lan}}
}

func TestResolve(t *testing.T) {
	const (
		nx      = "NXDOMAIN"
		nodata  = "NODATA"
		refused = "REFUSED"
		forward = "FORWARD"
	)
	v := view()
	cases := []struct {
		name string
		from Asker
		want string // addresses, or one of the outcomes above
	}{
		// The plain name, by who asks.
		{"api.payments.kevaso", FromSilo, "10.64.2.7"},
		{"api.payments.kevaso", FromHost, "10.64.2.7"},
		{"api.payments.kevaso", FromNetwork, "10.0.0.5"},
		{"api.payments.kevaso", FromOutside, "51.38.10.20"},
		{"API.Payments.kevaso.", FromSilo, "10.64.2.7"},
		// Not reachable from there: no answer. db opens nothing on a host.
		{"db.payments.kevaso", FromOutside, nodata},
		{"db.payments.kevaso", FromNetwork, nodata},
		{"db.payments.kevaso", FromSilo, "10.64.3.4"},
		// A machine on the network gets external when there's no internal answer.
		{"slow.payments.kevaso", FromNetwork, nodata}, // held: nothing anywhere
		// Each network by name, for those who may.
		{"api.payments.mesh.kevaso", FromHost, "10.64.2.7"},
		{"api.payments.internal.kevaso", FromHost, "10.0.0.5"},
		{"api.payments.external.kevaso", FromHost, "51.38.10.20"},
		{"api.payments.internal.kevaso", FromNetwork, "10.0.0.5"},
		{"api.payments.external.kevaso", FromNetwork, "51.38.10.20"},
		{"api.payments.external.kevaso", FromOutside, "51.38.10.20"},
		{"api.payments.mesh.kevaso", FromNetwork, refused},
		{"api.payments.internal.kevaso", FromOutside, refused},
		{"api.payments.mesh.kevaso", FromOutside, refused},
		// A silo: services by plain name only.
		{"api.payments.mesh.kevaso", FromSilo, refused},
		{"api.payments.external.kevaso", FromSilo, refused},
		{"ovh-1.mesh.kevaso", FromSilo, refused},
		// Hosts.
		{"ovh-1.mesh.kevaso", FromHost, "10.63.0.2"},
		{"ovh-1.internal.kevaso", FromHost, "10.0.0.5"},
		{"ovh-1.external.kevaso", FromHost, "51.38.10.20"},
		{"lan-1.external.kevaso", FromHost, nodata}, // it has none
		{"ovh-1.internal.kevaso", FromNetwork, "10.0.0.5"},
		{"ovh-1.mesh.kevaso", FromNetwork, refused},
		{"ovh-1.external.kevaso", FromOutside, "51.38.10.20"},
		{"ovh-1.internal.kevaso", FromOutside, refused},
		{"nope.mesh.kevaso", FromHost, nx},
		// Held by routeWhen: the name exists, with no address.
		{"slow.payments.kevaso", FromSilo, nodata},
		{"slow.payments.external.kevaso", FromHost, nodata},
		// The service has the name, not the silo; a silo without a service has none.
		{"api-blue.payments.kevaso", FromSilo, nx},
		{"worker.payments.kevaso", FromSilo, nx},
		{"nope.payments.kevaso", FromSilo, nx},
		// A Service: its cluster IP on the mesh, its endpoints' hosts on the others.
		{"rpc.web3.kevaso", FromSilo, "10.65.0.1"},
		{"rpc.web3.internal.kevaso", FromHost, "192.168.1.20"},
		{"rpc.web3.kevaso", FromNetwork, "192.168.1.20"},
		{"rpc.web3.kevaso", FromOutside, nodata},
		{"rpc-0.web3.kevaso", FromSilo, "10.64.3.5"},
		// Shapes that aren't names.
		{"kevaso", FromHost, nx},
		{"api.kevaso", FromSilo, nx},
		{"a.b.c.kevaso", FromHost, nx},
		// Short names, inside a silo of payments.
		{"api", FromSilo, "10.64.2.7"},
		{"rpc.web3", FromSilo, "10.65.0.1"},
		{"example.com", FromSilo, forward},
		{"ubuntu.com.", FromSilo, forward},
		{"api", FromHost, forward}, // only silos have short names
	}
	for _, c := range cases {
		a := Resolve(Question{Name: c.name, From: c.from, Namespace: "payments"}, v)
		got := ""
		switch {
		case !a.InZone:
			got = forward
		case a.Refused:
			got = refused
		case !a.Found:
			got = nx
		case len(a.IPs) == 0:
			got = nodata
		default:
			var ips []string
			for _, ip := range a.IPs {
				ips = append(ips, ip.String())
			}
			got = strings.Join(ips, " ")
		}
		if got != c.want {
			t.Errorf("%s asks %s: %s, want %s", c.from, c.name, got, c.want)
		}
	}
	// Another suffix: kevaso names are no longer ours.
	v.Suffix = "corp"
	if a := Resolve(Question{Name: "api.payments.corp", From: FromSilo}, v); len(a.IPs) != 1 {
		t.Errorf("suffix corp: %+v", a)
	}
	if a := Resolve(Question{Name: "api.payments.kevaso", From: FromHost}, v); a.InZone {
		t.Errorf("suffix corp, kevaso asked: %+v", a)
	}
}

func TestOwnerAndHolder(t *testing.T) {
	v := view()
	if s, _ := Owner("payments", "api", v.Silos, v.Services); s == nil || s.Name != "api-blue" {
		t.Fatalf("api's owner: %v", s)
	}
	if got := Holder("payments", "api", "silo/api-green", v.Silos, v.Services); got != "silo/api-blue" {
		t.Errorf("holder %q", got)
	}
	if got := Holder("payments", "api", "silo/api-blue", v.Silos, v.Services); got != "" {
		t.Errorf("its own name: %q", got)
	}
	if got := Holder("web3", "rpc", "silo/x", v.Silos, v.Services); got != "service/rpc" {
		t.Errorf("a Service's name: %q", got)
	}
	for _, ns := range []string{"mesh", "internal", "external"} {
		if !Reserved(ns) {
			t.Errorf("%s isn't reserved", ns)
		}
	}
	if Reserved("payments") {
		t.Error("payments reserved")
	}
}
