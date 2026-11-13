package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"

	"kevaso.com/core/internal/pki"
)

// startTest starts a one-member etcd on loopback in a temp dir, stopped when the test ends.
func startTest(t *testing.T, ca *pki.CA) *Server {
	t.Helper()
	s, err := Start(context.Background(), Config{Name: "cp1", Dir: filepath.Join(t.TempDir(), "etcd"), CA: ca,
		ClientListen: "127.0.0.1:0", UnsafeNoFsync: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestSingleMemberOnLoopbackTLS(t *testing.T) {
	ca, err := pki.NewCA("c", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := startTest(t, ca)
	if len(s.Etcd.Peers) != 0 {
		t.Fatalf("a member without PeerListen listens for peers: %d listeners", len(s.Etcd.Peers))
	}
	cli, err := s.Client()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := cli.Put(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	if r, err := cli.Get(ctx, "k"); err != nil || len(r.Kvs) != 1 || string(r.Kvs[0].Value) != "v" {
		t.Fatalf("get = %v, %v", r, err)
	}

	// A host's client certificate from the same CA is not a member's: refused.
	keyPEM, csrPEM, err := pki.NewKeyAndCSR(pki.Identity{Type: "host", Name: "hv1", Role: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := ca.SignCSR(csrPEM, pki.Identity{Type: "host", Name: "hv1", Role: "worker"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	hostCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got := try(t, s.ClientURL, ca.Pool(), []tls.Certificate{hostCert}); got == nil {
		t.Fatal("a host certificate could use etcd")
	}
	if got := try(t, s.ClientURL, ca.Pool(), nil); got == nil {
		t.Fatal("no client certificate could use etcd")
	}
}

func try(t *testing.T, url string, pool *x509.CertPool, certs []tls.Certificate) error {
	t.Helper()
	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{url}, DialTimeout: 2 * time.Second, Logger: zap.NewNop(),
		TLS: &tls.Config{RootCAs: pool, Certificates: certs, MinVersion: tls.VersionTLS12}})
	if err != nil {
		return err
	}
	defer func() { _ = cli.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = cli.Get(ctx, "k")
	return err
}

func TestMemberCert(t *testing.T) {
	ca, _ := pki.NewCA("c", time.Now())
	c, err := MemberCert(ca, []string{"cp1", "10.0.0.1", "cp1"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := c.Leaf
	if leaf.Subject.CommonName != MemberCN || len(leaf.DNSNames) != 1 || len(leaf.IPAddresses) != 1 {
		t.Fatalf("cert %v %v %v", leaf.Subject, leaf.DNSNames, leaf.IPAddresses)
	}
	for _, u := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{u}}); err != nil {
			t.Fatalf("usage %v: %v", u, err)
		}
	}
}
