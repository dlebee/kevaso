package apiserver

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"kevaso.com/core/api/client"
)

// APICertTTL is how long the API's serving certificate lasts. It is reissued at two thirds
// of that life, so a control plane that stays up keeps presenting a certificate clients trust.
const APICertTTL = 365 * 24 * time.Hour

// ServingCert is the API listener's certificate. GetCertificate serves the current one.
// Rotate replaces it once it is due.
type ServingCert struct {
	mu    sync.Mutex
	cert  *tls.Certificate
	issue func(time.Time) (tls.Certificate, error)
	now   func() time.Time
	log   func(string, ...any)
}

// NewServingCert serves initial and replaces it by calling issue when it is due at now.
func NewServingCert(initial tls.Certificate, issue func(time.Time) (tls.Certificate, error), now func() time.Time) *ServingCert {
	if now == nil {
		now = time.Now
	}
	c := initial
	return &ServingCert{cert: &c, issue: issue, now: now}
}

// SetLog is where a renewal is reported. Nil stays quiet.
func (s *ServingCert) SetLog(log func(string, ...any)) { s.log = log }

// GetCertificate presents the current serving certificate.
func (s *ServingCert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cert == nil {
		return nil, errors.New("no serving certificate")
	}
	return s.cert, nil
}

// Rotate replaces the certificate once it is past two thirds of its life. It reports whether
// it did.
func (s *ServingCert) Rotate() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.cert != nil && s.cert.Leaf != nil && !client.RenewDue(s.cert.Leaf.NotBefore, s.cert.Leaf.NotAfter, now) {
		return false, nil
	}
	c, err := s.issue(now)
	if err != nil {
		return false, err
	}
	s.cert = &c
	return true, nil
}

// Run renews the certificate until ctx ends, checking every interval.
func (s *ServingCert) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Hour
	}
	for {
		did, err := s.Rotate()
		if s.log != nil {
			if err != nil {
				s.log("api certificate: %v", err)
			} else if did {
				s.log("api certificate renewed")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
