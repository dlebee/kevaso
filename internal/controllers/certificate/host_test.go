package certificate_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"sync/atomic"
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
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kcc"
)

type countIssue struct {
	kcc.CertController
	n atomic.Int32
}

func (c *countIssue) Issue(ctx context.Context, r kcc.Request) ([][]byte, error) {
	c.n.Add(1)
	return c.CertController.Issue(ctx, r)
}

func TestAnUnassignedHostIsNotIssued(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer func() { cancel(); ts.Close() }()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "shop"}}); err != nil {
		t.Fatal(err)
	}
	if err := EnsureIssuers(ctx, c); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	builtin, err := BuiltinCertControllers(nil, nil, nil, ca, time.Now, nil).Get(IssuerInternal)
	if err != nil {
		t.Fatal(err)
	}
	cc := &countIssue{CertController: builtin}
	own := &v1.Certificate{TypeMeta: tm("Certificate"), ObjectMeta: meta.ObjectMeta{Name: "site", Namespace: "shop"},
		Spec: v1.CertificateSpec{Hosts: []string{"site.shop.kevaso"}, Issuer: IssuerInternal, SecretName: "site-tls"}}
	if err := c.Create(ctx, own); err != nil {
		t.Fatal(err)
	}
	key := store.Key{Kind: "Certificate", Namespace: "shop", Name: "site"}
	cur, err := st.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	var stored v1.Certificate
	if err := json.Unmarshal(cur.Data, &stored); err != nil {
		t.Fatal(err)
	}
	stored.Spec.Hosts = []string{"billing.example.com"}
	data, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(ctx, key, data, cur.Revision); err != nil {
		t.Fatal(err)
	}
	certs := informer.New(c, "Certificate")
	go certs.Run(ctx)
	for {
		if o, ok := certs.Get("shop", "site"); ok && o.(*v1.Certificate).Spec.Hosts[0] == "billing.example.com" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("the cache never had the unassigned host")
		case <-time.After(5 * time.Millisecond):
		}
	}
	ctrl := &Controller{Client: c, Store: st, Clock: clock.Real{}, Certificates: certs, CertControllers: kcc.Registry{IssuerInternal: cc}}
	if _, err := ctrl.Reconcile(ctx, engine.Key{Kind: "Certificate", Namespace: "shop", Name: "site"}); err != nil {
		t.Fatal(err)
	}
	if cc.n.Load() != 0 {
		t.Fatalf("an unassigned host was issued (%d)", cc.n.Load())
	}
	var got v1.Certificate
	if err := c.Get(ctx, "Certificate", "shop", "site", &got); err != nil {
		t.Fatal(err)
	}
	ready := meta.FindCondition(got.Status.Conditions, "Ready")
	if ready == nil || ready.Reason != "HostNotAllowed" {
		t.Fatalf("status %+v", got.Status.Conditions)
	}
}
