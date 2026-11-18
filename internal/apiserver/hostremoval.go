package apiserver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"kevaso.com/core/api/client"

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
	// Pending is a removal whose Host delete has not committed yet: the certificate is refused
	// for now (503, try again), not finally. finalizeHostRemoval clears it once the delete
	// commits; a pending record whose Host is gone or being deleted counts as final too.
	Pending bool `json:"pending,omitempty"`
}

func hostRemovalKey(name string) store.Key { return store.Key{Kind: hostRemovalKind, Name: name} }

// hostRemovalSnap is the removal record that stood before a delete, so a refused delete can put
// it back. ok is false when there was none: the record the delete wrote is removed instead.
type hostRemovalSnap struct {
	data  []byte
	ok    bool
	wrote int64 // the revision of the record this request wrote: only that one is undone
}

func (s *Server) hostRemovalSnap(ctx context.Context, name string) (hostRemovalSnap, error) {
	o, err := s.store.Get(ctx, hostRemovalKey(name))
	if errors.Is(err, store.ErrNotFound) {
		return hostRemovalSnap{}, nil
	}
	if err != nil {
		return hostRemovalSnap{}, err
	}
	return hostRemovalSnap{data: append([]byte(nil), o.Data...), ok: true}, nil
}

// restoreHostRemoval puts back the record a refused delete replaced. A host that had joined
// again keeps the serials issued after the earlier removal.
func (s *Server) restoreHostRemoval(ctx context.Context, name string, prev hostRemovalSnap) error {
	key := hostRemovalKey(name)
	// Another delete of this host went through meanwhile: its removal stands.
	if _, err := s.store.Get(ctx, store.Key{Kind: "Host", Name: name}); errors.Is(err, store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	for attempt := 0; attempt < 5; attempt++ {
		o, err := s.store.Get(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			return nil // not the record this request wrote: nothing of ours to undo
		}
		if err != nil {
			return err
		}
		if o.Revision != prev.wrote { // only the record this request wrote is undone
			return nil
		}
		if !prev.ok {
			if _, err := s.store.Delete(ctx, key, o.Revision); err != nil {
				if errors.Is(err, store.ErrConflict) {
					continue
				}
				return err
			}
			return nil
		}
		if _, err := s.store.Update(ctx, key, prev.data, o.Revision); err != nil {
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			return err
		}
		return nil
	}
	return fmt.Errorf("host %s: restoring the removal record kept conflicting", name)
}

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
func (s *Server) revokeHost(ctx context.Context, name string) (int64, error) {
	rec := hostRemovalRecord{RemovedAt: s.clock.Now().UTC().Truncate(time.Second), Pending: true}
	data, err := json.Marshal(rec)
	if err != nil {
		return 0, err
	}
	key := hostRemovalKey(name)
	for attempt := 0; attempt < 5; attempt++ {
		o, err := s.store.Get(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			c, err := s.store.Create(ctx, key, data)
			if err != nil {
				if errors.Is(err, store.ErrExists) {
					continue
				}
				return 0, err
			}
			return c.Revision, nil
		}
		if err != nil {
			return 0, err
		}
		u, err := s.store.Update(ctx, key, data, o.Revision)
		if err != nil {
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			return 0, err
		}
		return u.Revision, nil
	}
	return 0, fmt.Errorf("host %s: recording the removal kept conflicting", name)
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

// errHostRemoved is the final refusal of a removed host's certificate (reason HostRemoved, which
// the host acts on); errRemovalUnreadable is a refusal for now, the record couldn't be read.
var (
	errHostRemoved       = errors.New("HostRemoved")
	errRemovalUnreadable = errors.New("RemovalUnreadable")
)

// hostRefusal is the HTTP error for removedHostCert's refusal: 401 with reason HostRemoved for a
// removed host, 503 when the record can't be read. Only HostRemoved is final for the host.
func hostRefusal(err error) error {
	msg := strings.TrimPrefix(strings.TrimPrefix(err.Error(), errHostRemoved.Error()+": "), errRemovalUnreadable.Error()+": ")
	if errors.Is(err, errHostRemoved) {
		return errf(http.StatusUnauthorized, client.ReasonHostRemoved, "%s", msg)
	}
	return errf(http.StatusServiceUnavailable, "Unavailable", "%s", msg)
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
	if err == nil && rec.RemovedAt.IsZero() {
		err = errors.New("no removal time")
	}
	if err != nil { // the removal record can't be read: refuse rather than accept a certificate it may revoke
		return fmt.Errorf("%w: host %s: its removal record can't be read (%v); try again", errRemovalUnreadable, name, err)
	}
	serial := cert.SerialNumber.Text(16)
	if !cert.NotBefore.Before(rec.RemovedAt) && slices.Contains(rec.Serials, serial) {
		return nil // issued after the removal, by joining again
	}
	if rec.Pending && !s.hostGoing(ctx, name) { // a delete is under way and may still be refused: not final
		return fmt.Errorf("%w: host %s: a delete of this host is under way; try again", errRemovalUnreadable, name)
	}
	// a certificate issued before this host was removed is refused
	return fmt.Errorf("%w: host %s was removed from the cluster; join it again with kvoadm host add", errHostRemoved, name)
}

// hostGoing reports whether Host name is gone or marked for deletion. An error reading it is
// not "gone": the refusal stays the try-again one.
func (s *Server) hostGoing(ctx context.Context, name string) bool {
	o, err := s.store.Get(ctx, store.Key{Kind: "Host", Name: name})
	if errors.Is(err, store.ErrNotFound) {
		return true
	}
	if err != nil {
		return false
	}
	var h struct {
		Metadata struct {
			DeletionTimestamp *time.Time `json:"deletionTimestamp"`
		} `json:"metadata"`
	}
	return json.Unmarshal(o.Data, &h) == nil && h.Metadata.DeletionTimestamp != nil
}

// finalizeHostRemoval marks the removal record final once the Host delete committed: from then
// on the host's certificate gets the final refusal, and its streams are closed. A failure here
// leaves it pending, which hostGoing then answers as final.
func (s *Server) finalizeHostRemoval(ctx context.Context, name string) {
	key := hostRemovalKey(name)
	for attempt := 0; attempt < 5; attempt++ {
		o, err := s.store.Get(ctx, key)
		if err != nil {
			return
		}
		var rec hostRemovalRecord
		if json.Unmarshal(o.Data, &rec) != nil || !rec.Pending {
			return
		}
		rec.Pending = false
		data, err := json.Marshal(rec)
		if err != nil {
			return
		}
		if _, err := s.store.Update(ctx, key, data, o.Revision); errors.Is(err, store.ErrConflict) {
			continue
		}
		return
	}
}
