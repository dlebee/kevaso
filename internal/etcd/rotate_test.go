package etcd

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"kevaso.com/core/internal/pki"
)

// servedSerial is the serial of the certificate the member's client listener presents now.
func servedSerial(t *testing.T, s *Server) string {
	t.Helper()
	cur, err := s.CurrentCert()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", s.Etcd.Clients[0].Addr().String(), &tls.Config{RootCAs: s.ca.Pool(), Certificates: []tls.Certificate{cur}, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
}

func TestRotationWithoutRestart(t *testing.T) {
	ca, err := pki.NewCA("c", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := startTest(t, ca)
	cli, err := s.Client()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	before := servedSerial(t, s)
	end, err := s.CertNotAfter()
	if err != nil {
		t.Fatal(err)
	}
	// Not due a year out; due once within RenewBefore of the end.
	if did, err := s.RotateIfDue(time.Now(), MemberCertTTL, RenewBefore); err != nil || did {
		t.Fatalf("rotated a fresh certificate: %v %v", did, err)
	}
	if did, err := s.RotateIfDue(end.Add(-RenewBefore+time.Hour), MemberCertTTL, RenewBefore); err != nil || !did {
		t.Fatalf("didn't rotate a certificate due: %v %v", did, err)
	}
	after := servedSerial(t, s)
	if after == before {
		t.Fatal("the member still serves the old certificate")
	}
	// The member never restarted, and both the old client and a new one still work.
	if _, err := cli.Put(ctx, "k", "v"); err != nil {
		t.Fatalf("old client after rotation: %v", err)
	}
	c2, err := s.Client()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	if _, err := c2.Get(ctx, "k"); err != nil {
		t.Fatalf("new client after rotation: %v", err)
	}
}
