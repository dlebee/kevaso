package worker

import (
	"sync"

	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/names"
)

// What the network serves (K-097). The caches follow whatever control plane answers, an older
// one included: a held worker (§0.7) is still handed its answers. So while the worker is held,
// the rules, the DNS listeners and the egress gate serve the last state this worker trusted
// instead: what it last saved (the last state, laststate.go), read from disk at a start, kept as
// it was saved since. With nothing trusted (a first start that is held at once) nothing is.

// netState is one consistent view of the kinds the network uses.
type netState struct {
	// held: the worker is held, and this is the last trusted state; none: held with nothing
	// trusted (every list empty).
	held, none bool
	raw        map[string][]meta.Object // the lists, by kind

	silos   []*v1.Silo
	hosts   []*v1.Host
	grants  []*v1.Grant
	ings    []*v1.Ingress
	classes []*v1.IngressClass
	svcs    []*v1.Service
	leases  []*v1.Lease
	ips     []*v1.IP
}

// served picks what the network serves from: the caches, or while held the trusted state.
type served struct {
	held func() bool                   // nil: never held
	live map[string]*informer.Informer // by kind: the caches kept in the last state

	mu      sync.Mutex
	trusted map[string][]meta.Object // the last state trusted; nil: none
}

func newServed(held func() bool, kept ...*informer.Informer) *served {
	s := &served{held: held, live: map[string]*informer.Informer{}}
	for _, inf := range kept {
		s.live[inf.Kind()] = inf
	}
	return s
}

// trust makes st the last trusted state (what was just saved, or read from disk at a start).
func (s *served) trust(st map[string][]meta.Object) {
	s.mu.Lock()
	s.trusted = st
	s.mu.Unlock()
}

// snapshot is every cache's list now, by kind.
func (s *served) snapshot() map[string][]meta.Object {
	out := map[string][]meta.Object{}
	for kind, inf := range s.live {
		out[kind] = inf.List()
	}
	return out
}

// state is what to serve now. The caches are read before the hold is looked at: an older control
// plane's answer is judged (and the worker held) before a cache gets it, so a list read before a
// "not held" holds no such answer.
func (s *served) state() netState {
	live := s.snapshot()
	if s.held == nil || !s.held() {
		return stateOf(live)
	}
	s.mu.Lock()
	t := s.trusted
	s.mu.Unlock()
	if t == nil {
		return netState{held: true, none: true}
	}
	st := stateOf(t)
	st.held = true
	return st
}

func typed[T any](objs []meta.Object) []T {
	out := make([]T, 0, len(objs))
	for _, o := range objs {
		if t, ok := o.(T); ok {
			out = append(out, t)
		}
	}
	return out
}

func stateOf(m map[string][]meta.Object) netState {
	return netState{
		raw:     m,
		silos:   typed[*v1.Silo](m["Silo"]),
		hosts:   typed[*v1.Host](m["Host"]),
		grants:  typed[*v1.Grant](m["Grant"]),
		ings:    typed[*v1.Ingress](m["Ingress"]),
		classes: typed[*v1.IngressClass](m["IngressClass"]),
		svcs:    typed[*v1.Service](m["Service"]),
		leases:  typed[*v1.Lease](m["Lease"]),
		ips:     typed[*v1.IP](m["IP"]),
	}
}

// me is this host's own Host in the state (nil: none).
func (st netState) me(hostName string) *v1.Host {
	for _, h := range st.hosts {
		if h.Name == hostName {
			return h
		}
	}
	return nil
}

// names is the DNS view of the state.
func (st netState) names() names.View {
	return names.View{Silos: st.silos, Services: st.svcs, Hosts: st.hosts, IPs: st.ips, Suffix: v1.ClusterSuffix(st.hosts)}
}
