package provider_test

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/provider"
	"kevaso.com/core/internal/engine"
)

// Review (check-then-act) item 8, DNS: records are deleted for names the Ingress no longer
// lists, as cached. A name put back since must not be deleted: the Ingress is read fresh before
// any record is deleted.
func TestADNSNamePutBackSinceTheReadIsNotDeleted(t *testing.T) {
	x := newK037(t)
	x.must(x.c.Create(x.ctx, &v1.IngressClass{TypeMeta: tm037("IngressClass"), ObjectMeta: meta.ObjectMeta{Name: "web"},
		Spec: v1.IngressClassSpec{Controller: v1.IngressController{Driver: "nginx", Silo: "ingress", Namespace: "d"}, DNS: &v1.IngressDNS{Provider: "fake-dns", TTL: 120}}}))
	ing := &v1.Ingress{TypeMeta: tm037("Ingress"), ObjectMeta: meta.ObjectMeta{Name: "shop", Namespace: "d", Finalizers: []string{provider.FinalizerDNS}},
		Spec: v1.IngressSpec{IngressClass: "web", Hosts: []string{"a.example", "b.example"}, Rules: []v1.IngressRule{{Path: "/", Service: v1.IngressTarget{Name: "web", Port: "http"}}}}}
	x.must(x.c.Create(x.ctx, ing))
	ing.Status.Address, ing.Status.DNSNames = "198.51.100.9", []string{"a.example", "b.example"}
	x.must(x.c.UpdateStatus(x.ctx, ing))
	// b removed from the spec…
	var cur v1.Ingress
	x.must(x.c.Get(x.ctx, "Ingress", "d", "shop", &cur))
	cur.Spec.Hosts = []string{"a.example"}
	x.must(x.c.Update(x.ctx, &cur))
	ctl := &provider.IngressDNS{Client: x.c, Ingresses: x.frozen("Ingress"), Classes: x.frozen("IngressClass"), Plugins: x.reg, Cluster: "c"}
	// …and put back after the controller's read.
	x.must(x.c.Get(x.ctx, "Ingress", "d", "shop", &cur))
	cur.Spec.Hosts = []string{"a.example", "b.example"}
	x.must(x.c.Update(x.ctx, &cur))
	mark := len(x.fake.CallLog())
	if _, err := ctl.Reconcile(x.ctx, engine.Key{Kind: "Ingress", Namespace: "d", Name: "shop"}); err != nil {
		t.Fatal(err)
	}
	for _, call := range x.fake.CallLog()[mark:] {
		if strings.HasPrefix(call, "delete-record b.example") {
			t.Fatalf("deleted the record of a name the Ingress lists again: %q", call)
		}
	}
}
