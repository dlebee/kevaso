package worker

import (
	"context"
	"encoding/json"
	"maps"
	"net/netip"
	"path"
	"sync"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/sdk/kri"
)

// K-002: a silo's port on the bridge is bound to the address its runtime gave it when it made
// the silo, not when the agent writes status.siloIP (that is after the silo's init steps). Both
// bridge runtimes save that address (and a VM's MAC) in their state file on this host before they
// make the tap or veth, so the worker reads it from there; until it has, the port is closed (the
// rules are default-deny per port), so the order the runtime, the agent and this loop run in
// never leaves a port open.

// Bound is the address, and the MAC where the runtime fixed one, a silo's port was made with. IP6
// is its IPv6 address ("ip6" in the state file; invalid: it was given none).
type Bound struct {
	IP  netip.Addr
	IP6 netip.Addr
	MAC string
}

// stateHost is where the runtimes' state is read from (tests replace it).
var stateHost cloudhypervisor.Host = cloudhypervisor.Local{}

// LocalBindings reads the bridge runtimes' state on this host: tap → what it was made with. A
// state file binds only the tap of the silo it names, and only from that silo's own directory.
func LocalBindings(h cloudhypervisor.Host) map[string]Bound {
	out := map[string]Bound{}
	for _, pattern := range []string{cloudhypervisor.SilosDir + "/*/silo.json", cloudhypervisor.ContainersDir + "/*/state.json"} {
		paths, _ := h.Glob(pattern)
		for _, p := range paths {
			b, err := h.ReadFile(p)
			if err != nil {
				continue
			}
			var s struct {
				ID  kri.ID `json:"id"`
				IP  string `json:"ip"`
				IP6 string `json:"ip6"`
				MAC string `json:"mac"`
			}
			if json.Unmarshal(b, &s) != nil || s.ID.Name == "" || s.ID.UID == "" {
				continue
			}
			ip, err := netip.ParseAddr(s.IP)
			if err != nil || !ip.Is4() {
				continue
			}
			n := cloudhypervisor.NamesFor(s.ID)
			if path.Base(path.Dir(p)) != n.Short {
				continue
			}
			bd := Bound{IP: ip, MAC: s.MAC}
			if ip6, err := netip.ParseAddr(s.IP6); err == nil && ip6.Is6() && !ip6.Is4In6() && ip6.Zone() == "" {
				bd.IP6 = ip6
			}
			out[n.Tap] = bd
		}
	}
	return out
}

// WithBindings gives each local silo the address and MAC its port was made with (they win over
// status.siloIP, which is a copy written later). A local silo with no binding keeps the address
// its status gives, without a MAC. Its IPv6 address is the binding's too (none if its port was
// made without one), and only inside this host's IPv6 silo subnet.
func WithBindings(view kni.Host, bound map[string]Bound) kni.Host {
	local := make([]kni.Silo, len(view.Local))
	for i, s := range view.Local {
		if b, ok := bound[s.Tap]; ok {
			s.IP, s.MAC, s.IP6 = b.IP, b.MAC, netip.Addr{}
			if view.Subnet6.Contains(b.IP6) {
				s.IP6 = b.IP6
			}
		}
		local[i] = s
	}
	view.Local = local
	return view
}

// watchBindings pokes when the runtimes' state on this host changes (a silo made or removed), so
// a new port is bound within about a second of its state file, before its silo boots.
func watchBindings(ctx context.Context, every time.Duration, read func() map[string]Bound, poke func()) {
	last := read()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if now := read(); !maps.Equal(now, last) {
			last = now
			poke()
		}
	}
}

// Bindings are the bindings of the ruleset that is loaded now (the last one nft took): the only
// addresses that say which port, so which silo, a packet came from.
type Bindings = loadedBindings

// NewBindings is an empty set: nothing bound until a ruleset is loaded.
func NewBindings() *Bindings { return &loadedBindings{} }

// Port is the port the loaded rules bind ip to (agent.Agent.Bound).
func (l *loadedBindings) Port(ip netip.Addr) (string, bool) { return l.tap(ip) }

type loadedBindings struct {
	mu   sync.Mutex
	byIP map[netip.Addr]string // address → tap
}

func (l *loadedBindings) set(bs []kni.Binding) {
	m := map[netip.Addr]string{}
	for _, b := range bs {
		m[b.IP] = b.Tap
	}
	l.mu.Lock()
	l.byIP = m
	l.mu.Unlock()
}

// tap is the port the loaded rules bind ip to.
func (l *loadedBindings) tap(ip netip.Addr) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.byIP[ip]
	return t, ok
}

// siloOnTap is the silo on this host whose port is tap.
func siloOnTap(hostName string, silos []*v1.Silo, tap string) (*v1.Silo, bool) {
	for _, s := range silos {
		if s.Status.Host == hostName && cloudhypervisor.NamesFor(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID}).Tap == tap {
			return s, true
		}
	}
	return nil, false
}

// boundNamespace is the namespace of the silo whose port the loaded rules bind an address to (the
// DNS listener's asker, ADR 0010 §5), never one a status merely claims.
func boundNamespace(hostName string, silos []*v1.Silo, l *loadedBindings, a netip.Addr) (string, bool) {
	tap, ok := l.tap(a)
	if !ok {
		return "", false
	}
	s, ok := siloOnTap(hostName, silos, tap)
	if !ok || s.DeletionTimestamp != nil {
		return "", false
	}
	return s.Namespace, true
}
