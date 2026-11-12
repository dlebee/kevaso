package integration

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controlplane"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/sdk/kcc"
)

// signing is a cert-controller registered on the control plane, like a wrapped tool would be.
type signing struct {
	ca  *pki.CA
	got chan kcc.Request
}

func (s *signing) Info() kcc.Info { return kcc.Info{Name: "signing", Description: "test"} }
func (s *signing) Issue(_ context.Context, r kcc.Request) ([][]byte, error) {
	s.got <- r
	return s.ca.SignServerCSR(r.CSR, r.Hosts, time.Now(), 30*24*time.Hour)
}

// failing is a cert-controller whose CA is down.
type failing struct{ calls atomic.Int32 }

func (f *failing) Info() kcc.Info { return kcc.Info{Name: "failing"} }
func (f *failing) Issue(context.Context, kcc.Request) ([][]byte, error) {
	f.calls.Add(1)
	return nil, errors.New("the CA is down")
}

// The certificate controller in a real control plane: an Ingress gets a Certificate and a Secret
// from the cluster's CA, and a Certificate whose Issuer names a registered cert-controller is
// issued by it, which only ever sees the CSR.
func TestCertificatesInAControlPlane(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvc")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	other, _ := pki.NewCA("other", time.Now())
	sg := &signing{ca: other, got: make(chan kcc.Request, 4)}
	fl := &failing{}
	cp, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", Address: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 100 * time.Millisecond,
		CertControllers: kcc.Registry{"signing": sg, "failing": fl}})
	if err != nil {
		t.Fatal(err)
	}
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	for _, n := range []string{"kevaso-system", "payments"} {
		if err := admin.Create(ctx, ns(n)); err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range []meta.Object{
		&v1.IngressClass{TypeMeta: tm("IngressClass"), ObjectMeta: meta.ObjectMeta{Name: "private"},
			Spec: v1.IngressClassSpec{Controller: v1.SiloRef{Silo: "ingress", Namespace: "kevaso-system"}}},
		&v1.Ingress{TypeMeta: tm("Ingress"), ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "payments"},
			Spec: v1.IngressSpec{IngressClass: "private", Hosts: []string{"api.payments.kevaso"},
				Rules: []v1.IngressRule{{Path: "/", Silo: v1.IngressTarget{Name: "api", Port: "http"}}}}},
		&v1.Issuer{TypeMeta: tm("Issuer"), ObjectMeta: meta.ObjectMeta{Name: "signing"},
			Spec: v1.IssuerSpec{Controller: "signing", Config: json.RawMessage(`{"team":"payments"}`)}},
		&v1.Issuer{TypeMeta: tm("Issuer"), ObjectMeta: meta.ObjectMeta{Name: "down"}, Spec: v1.IssuerSpec{Controller: "failing"}},
		&v1.Certificate{TypeMeta: tm("Certificate"), ObjectMeta: meta.ObjectMeta{Name: "flaky", Namespace: "payments"},
			Spec: v1.CertificateSpec{Hosts: []string{"flaky.example.com"}, Issuer: "down", SecretName: "flaky-tls"}},
		&v1.Certificate{TypeMeta: tm("Certificate"), ObjectMeta: meta.ObjectMeta{Name: "billing", Namespace: "payments"},
			Spec: v1.CertificateSpec{Hosts: []string{"billing.example.com"}, Issuer: "signing", SecretName: "billing-tls"}},
	} {
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	ready := func(name string) *v1.Certificate {
		t.Helper()
		for ctx.Err() == nil {
			var c v1.Certificate
			if admin.Get(ctx, "Certificate", "payments", name, &c) == nil {
				if cd := meta.FindCondition(c.Status.Conditions, "Ready"); cd != nil && cd.Status == meta.ConditionTrue {
					return &c
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("certificate %s never became ready", name)
		return nil
	}
	api := ready(v1.CertificateFor(&v1.Ingress{ObjectMeta: meta.ObjectMeta{Name: "api"}}))
	if api.Spec.Issuer != "internal-ca" || api.Status.NotAfter == nil {
		t.Errorf("the Ingress's certificate: %+v", api)
	}
	ready("billing")
	select {
	case r := <-sg.got:
		if r.Issuer != "signing" || string(r.Config) != `{"team":"payments"}` || r.Hosts[0] != "billing.example.com" {
			t.Errorf("the cert-controller got %+v", r)
		}
		csr, err := x509.ParseCertificateRequest(r.CSR)
		if err != nil || csr.DNSNames[0] != "billing.example.com" {
			t.Errorf("not a CSR for the host: %v", err)
		}
	default:
		t.Fatal("the registered cert-controller was never called")
	}
	// A failing CA is tried once, then left alone for a minute: not hammered on every status write.
	time.Sleep(2 * time.Second)
	var flaky v1.Certificate
	if err := admin.Get(ctx, "Certificate", "payments", "flaky", &flaky); err != nil {
		t.Fatal(err)
	}
	if n := fl.calls.Load(); n != 1 || flaky.Status.FailedAttempts != 1 || flaky.Status.NextAttempt == nil ||
		flaky.Status.NextAttempt.Sub(time.Now()) < 50*time.Second {
		t.Errorf("after a failure: %d calls, status %+v", n, flaky.Status)
	}
	_ = cp
}
