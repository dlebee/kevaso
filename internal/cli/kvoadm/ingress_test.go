package kvoadm

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	kicdrivers "kevaso.com/core/builtin/kic"
)

// kvoadm ingress install: one command for a class served by the vendor's proxy image behind a
// loadBalancer service.
func TestIngressObjects(t *testing.T) {
	o, err := parseIngress([]string{"install", "--public", "--option", "worker-connections=4096"})
	if err != nil {
		t.Fatal(err)
	}
	silo, class, err := IngressObjects(o, kicdrivers.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	if silo.Namespace != "kevaso-system" || silo.Name != "ingress-public" || silo.Spec.Image != "docker.io/library/nginx:1.27" || silo.Spec.Runtime != "docker" {
		t.Fatalf("silo %+v", silo.ObjectMeta)
	}
	sv := silo.Spec.Service
	if sv.Expose != v1.ExposeLoadBalancer || sv.LoadBalancer.Class != v1.LBWorkerIP || len(sv.Ports) != 2 || sv.Ports[0] != (v1.ServicePort{Name: "http", Port: 80}) || sv.Ports[1].Port != 443 {
		t.Fatalf("service %+v", sv)
	}
	if !class.Spec.Public || class.Spec.Controller.Driver != "nginx" || !class.Spec.Controller.Runs(silo) || class.Spec.Controller.Options["worker-connections"] != "4096" {
		t.Fatalf("class %+v", class.Spec)
	}
	o.Options = map[string]string{"workers": "1"}
	if _, _, err := IngressObjects(o, kicdrivers.Builtin()); err == nil || !strings.Contains(err.Error(), "unknown option workers") {
		t.Fatalf("an unknown option: %v", err)
	}
	o, _ = parseIngress([]string{"install", "--driver", "traefik"})
	if _, _, err := IngressObjects(o, kicdrivers.Builtin()); err == nil || !strings.Contains(err.Error(), "caddy, kong, nginx") {
		t.Fatalf("an unknown driver: %v", err)
	}
	if _, err := parseIngress([]string{"install", "--nope"}); err == nil {
		t.Fatal("an unknown flag")
	}
}
