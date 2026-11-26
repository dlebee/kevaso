package apiserver

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin"
)

// Admission asks the providers what they declared (networking v2): balancers, Provider IPs,
// their annotations, and a kept IP in front of a balancer.
func TestProvidersAreAskedAtAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetNetworking(plugins.Static{
		"linode": {ProviderIPs: true, LoadBalancers: true, Regions: []string{"us-ord"},
			Annotations: []kplugin.Annotation{{Key: "nodebalancer", Type: "string"}, {Key: "tag", Type: "string", On: []string{kplugin.OnIP}}}},
		"azure": {ProviderIPs: true, LoadBalancers: true, FrontWithIP: true},
		"dns":   {},
	})
	c, done := srv.InProcess()
	defer done()
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}); err != nil {
		t.Fatal(err)
	}
	silo := func(name, provider, ip string, ann map[string]string) *v1.Silo {
		return &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Ports: []v1.SiloPort{{Name: "web", Port: 80}},
				Services: []v1.SiloService{{Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: provider, IP: ip},
					Annotations: ann, Ports: []v1.ServicePort{{Port: "web"}}}}}}
	}
	ip := func(name, provider, region string, ann map[string]string) *v1.IP {
		return &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d", Annotations: ann},
			Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: provider, Region: region}}
	}
	refused := func(what string, obj meta.Object, want string) {
		t.Helper()
		if err := c.Create(ctx, obj); codeOf(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want 422 saying %q", what, err, want)
		}
	}
	admitted := func(what string, obj meta.Object) {
		t.Helper()
		if err := c.Create(ctx, obj); err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
	admitted("a linode balancer", silo("a", "linode", "", map[string]string{"linode.kevaso.com/nodebalancer": "edge"}))
	refused("a provider not installed", silo("b", "gcp", "", nil), "installed are")
	refused("a provider that makes no balancers", silo("c", "dns", "", nil), "services[0].loadBalancer")
	refused("a misspelled annotation", silo("d", "linode", "", map[string]string{"linode.kevaso.com/nodebalancr": "edge"}), "nodebalancr")
	refused("an IP's annotation on a service", silo("e", "linode", "", map[string]string{"linode.kevaso.com/tag": "x"}), "linode.kevaso.com/tag")
	refused("a kept IP in front of a NodeBalancer", silo("f", "linode", "edge", nil), "has an address of its own")
	admitted("a kept IP in front of an Azure balancer", silo("g", "azure", "front", nil))

	admitted("a Provider IP", ip("edge", "linode", "us-ord", map[string]string{"linode.kevaso.com/tag": "web"}))
	refused("a region the provider doesn't serve", ip("far", "linode", "eu-west", nil), "eu-west")
	refused("a provider that makes no IPs", ip("x", "dns", "us-ord", nil), "spec:")
	refused("a service's annotation on an IP", ip("y", "linode", "us-ord", map[string]string{"linode.kevaso.com/nodebalancer": "edge"}), "nodebalancer")

	svc := &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "d", Annotations: map[string]string{"linode.kevaso.com/nodebalancr": "x"}},
		Spec: v1.ServiceSpec{Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "linode"}, Selector: map[string]string{"app": "rpc"},
			Ports: []v1.ServicePortSpec{{Name: "rpc", Port: 8545}}}}
	refused("a Service's misspelled annotation", svc, "nodebalancr")
	set := &v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "pool", Namespace: "d"},
		Spec: v1.SiloSetSpec{Instances: 1, Template: v1.SiloTemplate{SiloSpec: silo("pool", "gcp", "", nil).Spec}}}
	refused("a template's balancer of a provider not installed", set, "template.services[0].loadBalancer")
}
