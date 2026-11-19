package apiserver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"kevaso.com/core/internal/store"
)

// errWatchEnded is a host-removal watch that stopped; it is opened again.
var errWatchEnded = errors.New("host removal watch ended")

// hostStreams is the open request of each host certificate on this member: watches and the
// tunnel. A removal recorded in the store cancels them here, including a removal another
// member wrote. A reconnect is then the "was removed" 401.
type hostStreams struct {
	mu      sync.Mutex
	next    uint64
	live    map[string]map[uint64]context.CancelFunc
	removed map[string]time.Time // RemovedAt already acted on
}

func (h *hostStreams) add(host string, cancel context.CancelFunc) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.live == nil {
		h.live = map[string]map[uint64]context.CancelFunc{}
	}
	if h.live[host] == nil {
		h.live[host] = map[uint64]context.CancelFunc{}
	}
	h.next++
	id := h.next
	h.live[host][id] = cancel
	return id
}

func (h *hostStreams) remove(host string, id uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m := h.live[host]; m != nil {
		delete(m, id)
		if len(m) == 0 {
			delete(h.live, host)
		}
	}
}

func (h *hostStreams) close(host string) {
	h.mu.Lock()
	m := h.live[host]
	delete(h.live, host)
	h.mu.Unlock()
	for _, cancel := range m {
		cancel()
	}
}

// noteRemoval reports whether RemovedAt is a removal this member has not closed for yet.
func (h *hostStreams) noteRemoval(name string, at time.Time) bool {
	if at.IsZero() {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.removed == nil {
		h.removed = map[string]time.Time{}
	}
	if !at.After(h.removed[name]) {
		return false
	}
	h.removed[name] = at
	return true
}

// watchHostRemovals follows the HostRemoval records in the store. Every member runs it, so a
// removal written on one member closes the watches and the tunnel on the others.
func (s *Server) watchHostRemovals() {
	for {
		if err := s.watchHostRemovalsOnce(context.Background()); err != nil {
			time.Sleep(time.Second)
		}
	}
}

func (s *Server) watchHostRemovalsOnce(ctx context.Context) error {
	objs, rev, err := s.store.List(ctx, store.Selector{Kind: hostRemovalKind})
	if err != nil {
		return err
	}
	for _, o := range objs {
		s.closeIfRemoved(o.Name, o.Data)
	}
	ch, err := s.store.Watch(ctx, store.Selector{Kind: hostRemovalKind}, rev)
	if err != nil {
		return err
	}
	for ev := range ch {
		if ev.Type == store.Deleted {
			continue
		}
		s.closeIfRemoved(ev.Object.Name, ev.Object.Data)
	}
	return errWatchEnded
}

// trackHost cancels ctx when this host is removed, including a removal another member recorded.
// stop drops the registration when the request ends.
func (s *Server) trackHost(ctx context.Context, name string, cert *x509.Certificate) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	id := s.hostStreams.add(name, cancel)
	if cert != nil {
		if _, err := s.removedHostCert(ctx, name, cert); err != nil { // removed between the check and the registration
			cancel()
		}
	}
	return ctx, func() {
		cancel()
		s.hostStreams.remove(name, id)
	}
}

func (s *Server) closeIfRemoved(name string, data []byte) {
	var rec hostRemovalRecord
	if json.Unmarshal(data, &rec) != nil || rec.Pending { // a pending removal may still be refused: streams stay
		return
	}
	if !s.hostStreams.noteRemoval(name, rec.RemovedAt) {
		return
	}
	s.closeHostStreams(name)
}

// closeHostStreams ends host name's open watches and its tunnel on this member.
func (s *Server) closeHostStreams(name string) {
	s.hostStreams.close(name) // open watches, and the tunnel's request
	s.tunnels.close(name)     // the tunnel, on this member
}
