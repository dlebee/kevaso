package service_test

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/service"
)

// K-061: a LoadBalancer Service publishes outside only ports its silos open themselves
// (spec.service.ports) and not on a lease. One that targets a declared port the silo doesn't open,
// or opens only on an approved lease, had its node-port rule on the host regardless: anyone who may
// create a Service opened it with neither open nor approve on the silo's exposure. Such a silo is
// held, never an endpoint, and why names the port.
func TestK061ALoadBalancerServicePublishesOnlyWhatTheSiloOpens(t *testing.T) {
	app := map[string]string{"app": "api"}
	mk := func(name string, open ...v1.ServicePort) *v1.Silo {
		s := silo(name, "w1", "10.64.1.2", app, true)
		s.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 8080}, {Name: "debug", Port: 9229}}
		if len(open) > 0 {
			s.Spec.Service = &v1.SiloService{Ports: open}
		}
		return s
	}
	opens := mk("opens", v1.ServicePort{Port: "http"}, v1.ServicePort{Port: "debug"})
	leased := mk("leased", v1.ServicePort{Port: "http"}, v1.ServicePort{Port: "debug", HostPort: []string{v1.NetworkExternal}, Lease: &v1.PortLease{}})
	unopened := mk("unopened", v1.ServicePort{Port: "http"})
	svc := func(typ string) *v1.Service {
		return &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "web3"},
			Spec: v1.ServiceSpec{Selector: app, RouteWhen: "running", Type: typ, LoadBalancerClass: "nb",
				Ports: []v1.ServicePortSpec{{Name: "web", Port: 80, TargetPort: "http"}, {Name: "debug", Port: 9229}}}}
	}
	routed, held := service.Split(svc(v1.ServiceLoadBalancer), []*v1.Silo{opens, leased, unopened})
	if len(routed) != 1 || routed[0].Silo != "opens" {
		t.Fatalf("routed: %+v, want only the silo that opens both ports", routed)
	}
	why := map[string]string{}
	for _, h := range held {
		why[h.Silo] = h.Reason
	}
	if r := why["leased"]; !strings.Contains(r, "debug") || !strings.Contains(r, "lease") {
		t.Errorf("leased: held %q, want it to name port debug and its lease", r)
	}
	if r := why["unopened"]; !strings.Contains(r, "debug") || !strings.Contains(r, "spec.service.ports") {
		t.Errorf("unopened: held %q, want it to name port debug and where to open it", r)
	}
	// A ClusterIP Service stays on the mesh: unchanged.
	if routed, _ := service.Split(svc(v1.ServiceClusterIP), []*v1.Silo{opens, leased, unopened}); len(routed) != 3 {
		t.Errorf("ClusterIP: routed %d, want 3", len(routed))
	}
}
