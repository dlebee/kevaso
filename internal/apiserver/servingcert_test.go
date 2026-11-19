package apiserver

import (
	"crypto/tls"
	"testing"
	"time"

	"kevaso.com/core/internal/pki"
)

// A serving certificate is reissued once two thirds of its life have passed, and the listener
// presents the new one.
func TestServingCertReissuesAtTwoThirds(t *testing.T) {
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start
	const ttl = 90 * 24 * time.Hour
	issue := func(at time.Time) (tls.Certificate, error) {
		return ca.ServerCert([]string{"api.example"}, at, ttl)
	}
	first, err := issue(start)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServingCert(first, issue, func() time.Time { return now })
	if did, err := s.Rotate(); err != nil || did {
		t.Fatalf("a fresh certificate was replaced: %v %v", did, err)
	}
	now = start.Add(30 * 24 * time.Hour)
	if did, err := s.Rotate(); err != nil || did {
		t.Fatalf("replaced at 30 of 90 days: %v %v", did, err)
	}
	now = start.Add(60 * 24 * time.Hour)
	if did, err := s.Rotate(); err != nil || !did {
		t.Fatalf("kept at two thirds of its life: %v %v", did, err)
	}
	got, err := s.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Fatalf("presented certificate still ends %s", got.Leaf.NotAfter)
	}
}
