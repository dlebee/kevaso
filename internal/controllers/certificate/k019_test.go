package certificate_test

import (
	"context"
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
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kcc"
)

type countingCC struct {
	kcc.CertController
	issued atomic.Int32
}

func (c *countingCC) Issue(ctx context.Context, r kcc.Request) ([][]byte, error) {
	c.issued.Add(1)
	return c.CertController.Issue(ctx, r)
}

// K-019: the certificate controller wrote and deleted the Secret a Certificate names by that name
// alone, with the control plane's own power: a Certificate (or an Ingress) naming someone else's
// Secret overwrote it with a certificate, and removing it deleted that Secret. It must only ever
// write or delete a Secret it made for that very Certificate, proven by a marker it puts there.
func TestK019OnlyTheCertificatesOwnSecretIsWrittenOrDeleted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	st := store.NewMemory(0)
	srv, _ := apiserver.New(st, clock.Real{})
	key, err := kms.OpenLocal(t.TempDir() + "/k.json")
	if err != nil {
		t.Fatal(err)
	}
	srv.SetVault(&secrets.Vault{Store: st, KMS: key, Now: time.Now})
	ts := httptest.NewServer(srv)
	defer func() { cancel(); ts.Close() }() // stop the watches first, or Close waits for them
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "shop"}})
	if err := EnsureIssuers(ctx, c); err != nil {
		t.Fatal(err)
	}
	ca, _ := pki.NewCA("test", time.Now())
	builtin, _ := BuiltinCertControllers(nil, nil, nil, ca, time.Now, nil).Get(IssuerInternal)
	cc := &countingCC{CertController: builtin}
	certs, ings := informer.New(c, "Certificate"), informer.New(c, "Ingress")
	go certs.Run(ctx)
	go ings.Run(ctx)
	ctrl := &Controller{Client: c, Clock: clock.Real{}, Certificates: certs, Ingresses: ings, CertControllers: kcc.Registry{IssuerInternal: cc}}
	// reconcile runs the controller on a Certificate once the cache has it as ok says.
	reconcile := func(name string, ok func(*v1.Certificate) bool) {
		t.Helper()
		for {
			if o, found := certs.Get("shop", name); found && ok(o.(*v1.Certificate)) {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatalf("the cache never had %s", name)
			case <-time.After(5 * time.Millisecond):
			}
		}
		if _, err := ctrl.Reconcile(ctx, engine.Key{Kind: "Certificate", Namespace: "shop", Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	anyCert := func(*v1.Certificate) bool { return true }

	// Someone's database password, and a Certificate (made by hand, or for an Ingress) naming it.
	db := &v1.Secret{TypeMeta: tm("Secret"), ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "shop"}}
	db.Spec.Value = []byte("hunter2")
	if err := c.Create(ctx, db); err != nil {
		t.Fatal(err)
	}
	// A label is anyone's to write: it proves nothing.
	bad := &v1.Certificate{TypeMeta: tm("Certificate"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "shop", Labels: map[string]string{LabelIngress: "web"}},
		Spec: v1.CertificateSpec{Hosts: []string{"web.shop.kevaso"}, Issuer: IssuerInternal, SecretName: "db"}}
	if err := c.Create(ctx, bad); err != nil {
		t.Fatal(err)
	}
	var got v1.Certificate
	reconcile("web", anyCert)
	value := func(name string) string {
		var v client.SecretValue
		if err := c.Call(ctx, "GET", "/apis/kevaso/v1/namespaces/shop/secrets/"+name+"/value", nil, &v); err != nil {
			return "(" + err.Error() + ")"
		}
		return string(v.Value)
	}
	if v := value("db"); v != "hunter2" {
		t.Fatalf("someone else's Secret was overwritten: %.40q", v)
	}
	if n := cc.issued.Load(); n != 0 {
		t.Fatalf("a certificate was ordered (%d) for a Secret it may not write", n)
	}
	_ = c.Get(ctx, "Certificate", "shop", "web", &got)
	if r := meta.FindCondition(got.Status.Conditions, "Ready"); r == nil || r.Status != meta.ConditionFalse || r.Reason != ReasonSecretNotOwned {
		t.Fatalf("the Certificate doesn't say why: %+v", got.Status.Conditions)
	}

	// Its own Secret: made with the marker, written again on renewal.
	own := &v1.Certificate{TypeMeta: tm("Certificate"), ObjectMeta: meta.ObjectMeta{Name: "site", Namespace: "shop", Labels: map[string]string{LabelIngress: "site"}},
		Spec: v1.CertificateSpec{Hosts: []string{"site.shop.kevaso"}, Issuer: IssuerInternal, SecretName: "site-tls"}}
	if err := c.Create(ctx, own); err != nil {
		t.Fatal(err)
	}
	reconcile("site", anyCert)
	_ = c.Get(ctx, "Certificate", "shop", "site", &got)
	past := time.Now().Add(-time.Hour)
	got.Status.RenewAfter = &past // due again
	if err := c.UpdateStatus(ctx, &got); err != nil {
		t.Fatal(err)
	}
	reconcile("site", func(x *v1.Certificate) bool {
		return x.Status.RenewAfter != nil && x.Status.RenewAfter.Before(time.Now())
	})
	_ = c.Get(ctx, "Certificate", "shop", "site", &got)
	var sec v1.Secret
	if err := c.Get(ctx, "Secret", "shop", "site-tls", &sec); err != nil || sec.Annotations[AnnotationCertificateUID] != string(got.UID) {
		t.Fatalf("its own Secret: %+v %v", sec.ObjectMeta, err)
	}
	if n := cc.issued.Load(); n != 2 {
		t.Fatalf("issued %d times, want 2", n)
	}

	// Both Ingresses gone: the controller removes their Certificates, and only the Secret it made.
	ings.WaitSynced(ctx)
	for _, ing := range []string{"web", "site"} {
		if _, err := ctrl.IngressController().Reconcile(ctx, engine.Key{Kind: "Ingress", Namespace: "shop", Name: ing}); err != nil {
			t.Fatal(err)
		}
	}
	if v := value("db"); v != "hunter2" {
		t.Fatalf("someone else's Secret was deleted with the Certificate: %s", v)
	}
	if err := c.Get(ctx, "Secret", "shop", "site-tls", &sec); !client.IsNotFound(err) {
		t.Fatalf("its own Secret stayed: %v", err)
	}
}
