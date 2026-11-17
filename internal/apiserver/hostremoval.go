package apiserver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	"kevaso.com/core/internal/store"
)

// hostRemovalKind is the store kind of a host-certificate removal. It is not an API kind
// (the same idea as JoinToken): every control-plane member reads it from the store.
const hostRemovalKind = "HostRemoval"

// hostRemovalRecord is what a delete of Host NAME stores. RemovedAt is truncated to a second,
// which is the precision an x509 certificate keeps. Serials are certificates issued after that
// time; the list starts empty, so every certificate already issued is refused.
type hostRemovalRecord struct {
	RemovedAt time.Time `json:"removedAt"`
	Serials   []string  `json:"serials,omitempty"`
}

func hostRemovalKey(name string) store.Key { return store.Key{Kind: hostRemovalKind, Name: name} }

func (s *Server) hostRemoval(ctx context.Context, name string) (hostRemovalRecord, bool) {
	o, err := s.store.Get(ctx, hostRemovalKey(name))
	if err != nil {
		return hostRemovalRecord{}, false
	}
	var rec hostRemovalRecord
	if json.Unmarshal(o.Data, &rec) != nil || rec.RemovedAt.IsZero() {
		return hostRemovalRecord{}, false
	}
	return rec, true
}

// revokeHost records that certificates for name issued before now are no longer accepted.
// A later delete replaces the record, which drops serials issued after the previous one.
func (s *Server) revokeHost(ctx context.Context, name string) error {
	rec := hostRemovalRecord{RemovedAt: s.clock.Now().UTC().Truncate(time.Second)}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	key := hostRemovalKey(name)
	for attempt := 0; attempt < 5; attempt++ {
		o, err := s.store.Get(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			if _, err := s.store.Create(ctx, key, data); err != nil {
				if errors.Is(err, store.ErrExists) {
					continue
				}
				return err
			}
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := s.store.Update(ctx, key, data, o.Revision); err != nil {
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			return err
		}
		return nil
	}
	return fmt.Errorf("host %s: recording the removal kept conflicting", name)
}

// noteIssuedHostCert records the serial of a host certificate issued after a removal, so auth
// accepts it. A name that was never removed has no record and nothing is written.
func (s *Server) noteIssuedHostCert(ctx context.Context, name string, certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("issued certificate: not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	serial := cert.SerialNumber.Text(16)
	key := hostRemovalKey(name)
	for attempt := 0; attempt < 5; attempt++ {
		o, err := s.store.Get(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		var rec hostRemovalRecord
		if err := json.Unmarshal(o.Data, &rec); err != nil {
			return err
		}
		if slices.Contains(rec.Serials, serial) {
			return nil
		}
		rec.Serials = append(rec.Serials, serial)
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := s.store.Update(ctx, key, data, o.Revision); err != nil {
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			return err
		}
		return nil
	}
	return fmt.Errorf("host %s: recording the new certificate kept conflicting", name)
}

// removedHostCert refuses a host certificate issued before that host was removed.
// NotBefore is backdated by a minute and stored at second precision, so a serial issued after
// the removal is recorded too: a clock that disagrees between members cannot make an old
// certificate look new, and a new one is not refused for the backdate.
func (s *Server) removedHostCert(ctx context.Context, name string, cert *x509.Certificate) error {
	o, err := s.store.Get(ctx, hostRemovalKey(name))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	var rec hostRemovalRecord
	if err == nil {
		err = json.Unmarshal(o.Data, &rec)
	}
	if err != nil { // the removal record can't be read: refuse rather than accept a certificate it may revoke
		return fmt.Errorf("host %s: can't check whether it was removed from the cluster (%v); try again", name, err)
	}
	serial := cert.SerialNumber.Text(16)
	if cert.NotBefore.Before(rec.RemovedAt) || !slices.Contains(rec.Serials, serial) { // a certificate issued before this host was removed is refused
		return fmt.Errorf("host %s was removed from the cluster; join it again with kvoadm host add", name)
	}
	return nil
}
