package kvoadm

import (
	"reflect"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	kicdrivers "kevaso.com/core/builtin/kic"
)

// kvoadm ingress install: one command for a class served by the vendor's proxy image behind a
// service whose ports open on its host's external IP (or internal, or a load balancer).
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
	if want := []v1.SiloPort{{Name: "http", Port: 80}, {Name: "https", Port: 443}}; !reflect.DeepEqual(silo.Spec.Ports, want) {
		t.Fatalf("ports %+v", silo.Spec.Ports)
	}
	ext := []string{v1.NetworkExternal}
	if want := (&v1.SiloService{Ports: []v1.ServicePort{{Port: "http", HostPort: ext}, {Port: "https", HostPort: ext}}}); !reflect.DeepEqual(silo.Spec.Service, want) {
		t.Fatalf("service %+v", silo.Spec.Service)
	}
	if !class.Spec.Public || class.Spec.Controller.Driver != "nginx" || !class.Spec.Controller.Runs(silo) || class.Spec.Controller.Options["worker-connections"] != "4096" {
		t.Fatalf("class %+v", class.Spec)
	}
	// --host-port internal: on its host's internal IP; --lb-class: on a load balancer instead.
	o, _ = parseIngress([]string{"install", "--host-port", "internal"})
	if silo, _, err := IngressObjects(o, kicdrivers.Builtin()); err != nil || !reflect.DeepEqual(silo.Spec.Service.Ports[0].HostPort, []string{v1.NetworkInternal}) {
		t.Fatalf("--host-port internal: %+v %v", silo, err)
	}
	o, _ = parseIngress([]string{"install", "--lb-class", "linode-nodebalancer"})
	if silo, _, err := IngressObjects(o, kicdrivers.Builtin()); err != nil ||
		!reflect.DeepEqual(silo.Spec.Service, &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", LoadBalancer: true}, {Port: "https", LoadBalancer: true}},
			LoadBalancer: &v1.LoadBalancerSpec{Class: "linode-nodebalancer"}}) {
		t.Fatalf("--lb-class: %+v %v", silo, err)
	}
	if _, err := parseIngress([]string{"install", "--host-port", "external", "--lb-class", "ip-pool"}); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("--host-port and --lb-class: %v", err)
	}
	if _, err := parseIngress([]string{"install", "--host-port", "public"}); err == nil || !strings.Contains(err.Error(), "internal or external") {
		t.Fatalf("--host-port public: %v", err)
	}
	o, _ = parseIngress([]string{"install"})
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
