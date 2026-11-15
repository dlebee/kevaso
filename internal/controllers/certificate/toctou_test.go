package certificate_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	. "kevaso.com/core/internal/controllers/certificate"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/store"
)

// Review (check-then-act) item 8: the certificate controller removes the Certificate made for an
// Ingress (and its Secret) when the Ingress is gone from its cache. An Ingress recreated under
// the same name since (its Certificate still cached) must keep them: the Ingress is read fresh
// before anything is deleted.
func TestAnIngressRecreatedSinceTheReadKeepsItsCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	defer cancel()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "shop"}}))
	cert := &v1.Certificate{TypeMeta: tm("Certificate"), ObjectMeta: meta.ObjectMeta{Name: "web-tls", Namespace: "shop", Labels: map[string]string{LabelIngress: "web"}},
		Spec: v1.CertificateSpec{Hosts: []string{"shop.example"}, Issuer: IssuerInternal, SecretName: "web-tls"}}
	must(c.Create(ctx, cert))
	must(c.Create(ctx, &v1.IngressClass{TypeMeta: tm("IngressClass"), ObjectMeta: meta.ObjectMeta{Name: "public"},
		Spec: v1.IngressClassSpec{Controller: v1.IngressController{Driver: "nginx", Silo: "edge", Namespace: "shop"}}}))
	frozen := func(kind string) *informer.Informer {
		ictx, stop := context.WithCancel(ctx)
		inf := informer.New(c, kind)
		go inf.Run(ictx)
		if !inf.WaitSynced(ctx) {
			t.Fatalf("%s never synced", kind)
		}
		stop()
		return inf
	}
	ctrl := &Controller{Client: c, Clock: clock.Real{}, Certificates: frozen("Certificate"), Ingresses: frozen("Ingress"),
		Classes: frozen("IngressClass"), Silos: frozen("Silo"), Issuers: frozen("Issuer")}
	// The Ingress is back (deleted and made again; the cache saw neither).
	must(c.Create(ctx, &v1.Ingress{TypeMeta: tm("Ingress"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "shop"},
		Spec: v1.IngressSpec{IngressClass: "public", Hosts: []string{"shop.example"}, Rules: []v1.IngressRule{{Path: "/", Service: v1.IngressTarget{Name: "web", Port: "http"}}}}}))
	if _, err := ctrl.IngressController().Reconcile(ctx, engine.Key{Kind: "Ingress", Namespace: "shop", Name: "web"}); err != nil {
		t.Fatal(err)
	}
	var got v1.Certificate
	if err := c.Get(ctx, "Certificate", "shop", "web-tls", &got); err != nil || got.DeletionTimestamp != nil {
		t.Fatalf("the recreated Ingress's Certificate was deleted: %v", err)
	}
}
