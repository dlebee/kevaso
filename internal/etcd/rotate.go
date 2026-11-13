package etcd

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// MemberCertTTL is how long a member certificate is valid; RenewBefore is how long before its end
// it is replaced.
const (
	MemberCertTTL = 365 * 24 * time.Hour
	RenewBefore   = 30 * 24 * time.Hour
)

// NeedsRotation is whether a certificate valid until notAfter is due for replacement at now. Pure.
func NeedsRotation(notAfter, now time.Time, renewBefore time.Duration) bool {
	return !now.Before(notAfter.Add(-renewBefore))
}

// CertNotAfter is when the member's current certificate (on disk) ends.
func (s *Server) CertNotAfter() (time.Time, error) {
	b, err := os.ReadFile(s.files.cert)
	if err != nil {
		return time.Time{}, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return time.Time{}, fmt.Errorf("%s: not PEM", s.files.cert)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
}

// Rotate replaces the member's certificate and key with fresh ones valid for ttl from now. etcd
// reads the files at every handshake (its listeners and this package's clients alike), so new
// connections use the new certificate at once; open ones keep the old, still valid, one. Each
// member rotates its own, so the cluster never restarts for it.
func (s *Server) Rotate(now time.Time, ttl time.Duration) error {
	cert, err := MemberCert(s.ca, s.names, now, ttl)
	if err != nil {
		return err
	}
	kd, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	// The key first, then the certificate, each by rename: a handshake in between may fail once
	// (a pair that doesn't match) and is retried; it never reads a half-written file.
	if err := replaceFile(s.files.key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})); err != nil {
		return err
	}
	return replaceFile(s.files.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
}

// RotateIfDue rotates when the certificate is within renewBefore of its end at now; it says whether
// it did. The new certificate starts at the wall clock's now (peers check it against theirs).
func (s *Server) RotateIfDue(now time.Time, ttl, renewBefore time.Duration) (bool, error) {
	na, err := s.CertNotAfter()
	if err != nil {
		return false, err
	}
	if !NeedsRotation(na, now, renewBefore) {
		return false, nil
	}
	return true, s.Rotate(time.Now(), ttl)
}

// RunRotation checks the certificate every interval until ctx ends.
func (s *Server) RunRotation(ctx context.Context, now func() time.Time, every time.Duration, log func(string, ...any)) {
	for {
		if did, err := s.RotateIfDue(now(), MemberCertTTL, RenewBefore); err != nil {
			log("etcd member certificate: %v", err)
		} else if did {
			log("etcd member certificate renewed")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// CurrentCert is the member's certificate as a new connection would present it.
func (s *Server) CurrentCert() (tls.Certificate, error) {
	return tls.LoadX509KeyPair(s.files.cert, s.files.key)
}

// IsLearner reports whether this member is still a learner (no vote, no client requests yet).
func (s *Server) IsLearner() bool { return s.Etcd.Server.IsLearner() }

// WaitVoter waits until this member has been promoted (the leader's member controller does it once
// the member has caught up), checking every interval.
func (s *Server) WaitVoter(ctx context.Context, every time.Duration) error {
	for s.IsLearner() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
	return nil
}

func replaceFile(path string, data []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
