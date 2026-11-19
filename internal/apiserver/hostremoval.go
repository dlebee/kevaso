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
	// HostUID is the UID of the Host the pending delete is for: a Host of that name with
	// another UID was made after the delete committed, so the removal is final.
	HostUID string `json:"hostUID,omitempty"`
	// Prev is the record this pending one replaced, put back if the delete never commits.
	Prev json.RawMessage `json:"prev,omitempty"`
}

// pendingStale is how long a pending removal can stand with its Host unchanged before the
// sweep takes it for a delete that never committed (a member that stopped mid-delete).
const pendingStale = 2 * time.Minute

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
	var rec hostRemovalRecord
	if json.Unmarshal(o.Data, &rec) == nil && rec.Pending { // a delete that never finished: what stood before it
		if len(rec.Prev) == 0 {
			return hostRemovalSnap{}, nil
		}
		return hostRemovalSnap{data: append([]byte(nil), rec.Prev...), ok: true}, nil
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
func (s *Server) revokeHost(ctx context.Context, name, hostUID string, prev hostRemovalSnap) (int64, error) {
	rec := hostRemovalRecord{RemovedAt: s.clock.Now().UTC().Truncate(time.Second), Pending: true, HostUID: hostUID}
	if prev.ok {
		rec.Prev = prev.data
	}
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

// hostCertBound is the removal a host renew's check read. check is set for a renew and not for
// an enroll: joining again records the serial on whatever removal stands now. ok is false when
// the check read none. at, uid, rev and serials are that record. The serial is recorded only
// while the record is still that one, compared and swapped at its revision.
type hostCertBound struct {
	check   bool
	ok      bool
	at      time.Time
	uid     string
	rev     int64
	serials []string
}

// sameHostRemoval reports whether rec at rev is the removal bound judged, not a newer one.
// The check's revision is that record. A later revision is still that removal when its time
// and host are unchanged and it still carries the serials the check saw: another renew may
// have recorded one, or a pending removal may have been finalized. A replacement drops them.
func sameHostRemoval(bound hostCertBound, rec hostRemovalRecord, rev int64) bool {
	if !bound.ok {
		return false
	}
	if rev == bound.rev { // the record the check read
		return true
	}
	if !rec.RemovedAt.Equal(bound.at) || rec.HostUID != bound.uid {
		return false
	}
	for _, serial := range bound.serials {
		if !slices.Contains(rec.Serials, serial) {
			return false
		}
	}
	return true
}

// noteIssuedHostCert records the serial of a host certificate issued after a removal, so auth
// accepts it. A name that was never removed has no record and nothing is written. A renew
// (bound.check) records it only when the removal is still the one the check read. The update is
// a compare-and-swap on that record, and the record is read back before the certificate is
// returned. A newer removal records nothing.
func (s *Server) noteIssuedHostCert(ctx context.Context, name string, certPEM []byte, bound hostCertBound) error {
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
			if bound.check && bound.ok { // the removal this renew saw is gone
				return fmt.Errorf("%w: host %s was removed", errHostRemoved, name)
			}
			return nil
		}
		if err != nil {
			return err
		}
		var rec hostRemovalRecord
		if err := json.Unmarshal(o.Data, &rec); err != nil {
			return err
		}
		if bound.check && !sameHostRemoval(bound, rec, o.Revision) { // the removal this renew saw
			return fmt.Errorf("%w: host %s was removed", errHostRemoved, name)
		}
		if slices.Contains(rec.Serials, serial) {
			if err := s.issuedHostCertStill(ctx, name, serial, bound); err != nil {
				return err
			}
			return nil
		}
		rec.Serials = append(rec.Serials, serial)
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := s.store.Update(ctx, key, data, o.Revision); err != nil { // compare-and-swap: still the record just judged
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			return err
		}
		if err := s.issuedHostCertStill(ctx, name, serial, bound); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("host %s: recording the new certificate kept conflicting", name)
}

// issuedHostCertStill re-reads the removal after the serial was recorded. A renew is refused
// when that record is no longer the one the check read, or the serial is not on it. The serial
// is left where it was written: a replacement already dropped it, and deleting it here would
// hide a record that was not the one this renew saw.
func (s *Server) issuedHostCertStill(ctx context.Context, name, serial string, bound hostCertBound) error {
	if !bound.check {
		return nil
	}
	o, err := s.store.Get(ctx, hostRemovalKey(name))
	if err != nil {
		return fmt.Errorf("%w: host %s was removed", errHostRemoved, name)
	}
	var again hostRemovalRecord
	if json.Unmarshal(o.Data, &again) != nil || !sameHostRemoval(bound, again, o.Revision) || !slices.Contains(again.Serials, serial) {
		return fmt.Errorf("%w: host %s was removed", errHostRemoved, name)
	}
	return nil
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

// hostRemovalSeen is the removal removedHostCert read. ok is false when there was none.
type hostRemovalSeen struct {
	ok  bool
	rec hostRemovalRecord
	rev int64
}

// removedHostCert refuses a host certificate issued before that host was removed, and returns
// the removal that read judged (ok false: there was none). A renew binds its serial to this
// value instead of reading the removal again. NotBefore is backdated by a minute and stored at
// second precision, so a serial issued after the removal is recorded too: a clock that disagrees
// between members cannot make an old certificate look new, and a new one is not refused for the
// backdate.
func (s *Server) removedHostCert(ctx context.Context, name string, cert *x509.Certificate) (hostRemovalSeen, error) {
	o, err := s.store.Get(ctx, hostRemovalKey(name))
	if errors.Is(err, store.ErrNotFound) {
		return hostRemovalSeen{}, nil
	}
	var rec hostRemovalRecord
	if err == nil {
		err = json.Unmarshal(o.Data, &rec)
	}
	if err == nil && rec.RemovedAt.IsZero() {
		err = errors.New("no removal time")
	}
	if err != nil { // the removal record can't be read: refuse rather than accept a certificate it may revoke
		return hostRemovalSeen{}, fmt.Errorf("%w: host %s: its removal record can't be read (%v); try again", errRemovalUnreadable, name, err)
	}
	seen := hostRemovalSeen{ok: true, rec: rec, rev: o.Revision}
	serial := cert.SerialNumber.Text(16)
	if !cert.NotBefore.Before(rec.RemovedAt) && slices.Contains(rec.Serials, serial) {
		return seen, nil // issued after the removal, by joining again
	}
	if rec.Pending && !s.hostGoing(ctx, name, rec.HostUID) { // a delete is under way and may still be refused: not final
		return hostRemovalSeen{}, fmt.Errorf("%w: host %s: a delete of this host is under way; try again", errRemovalUnreadable, name)
	}
	// a certificate issued before this host was removed is refused
	return hostRemovalSeen{}, fmt.Errorf("%w: host %s was removed from the cluster; join it again with kvoadm host add", errHostRemoved, name)
}

// hostGoing reports whether Host name is gone, marked for deletion, or another Host than uid
// (made after the delete committed). An error reading it is not "gone": the refusal stays the
// try-again one.
func (s *Server) hostGoing(ctx context.Context, name, uid string) bool {
	o, err := s.store.Get(ctx, store.Key{Kind: "Host", Name: name})
	if errors.Is(err, store.ErrNotFound) {
		return true
	}
	if err != nil {
		return false
	}
	var h struct {
		Metadata struct {
			UID               string     `json:"uid"`
			DeletionTimestamp *time.Time `json:"deletionTimestamp"`
		} `json:"metadata"`
	}
	if json.Unmarshal(o.Data, &h) != nil {
		return false
	}
	return h.Metadata.DeletionTimestamp != nil || uid != "" && h.Metadata.UID != uid
}

// sweepHostRemovals settles pending removals a member left behind: final when the delete
// committed (the Host is gone, marked, or made again), and put back when the Host stood
// unchanged for pendingStale (the delete never committed). Every member runs it.
func (s *Server) sweepHostRemovals() {
	for {
		time.Sleep(30 * time.Second)
		s.sweepHostRemovalsOnce(context.Background())
	}
}

func (s *Server) sweepHostRemovalsOnce(ctx context.Context) {
	objs, _, err := s.store.List(ctx, store.Selector{Kind: hostRemovalKind})
	if err != nil {
		return
	}
	for _, o := range objs {
		var rec hostRemovalRecord
		if json.Unmarshal(o.Data, &rec) != nil || !rec.Pending {
			continue
		}
		if s.hostGoing(ctx, o.Name, rec.HostUID) {
			s.finalizeHostRemoval(ctx, o.Name) // the delete committed: final, and its streams close
			s.closeHostStreams(o.Name)         // here too, whether or not that write held
			continue
		}
		if s.clock.Now().Sub(rec.RemovedAt) < pendingStale {
			continue
		}
		key := hostRemovalKey(o.Name)
		if len(rec.Prev) == 0 { // a delete that never committed: what stood before it comes back
			_, _ = s.store.Delete(ctx, key, o.Revision)
		} else {
			_, _ = s.store.Update(ctx, key, rec.Prev, o.Revision)
		}
	}
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
		rec.Pending, rec.Prev = false, nil
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
