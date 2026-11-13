package worker

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/internal/names"
)

func heldSilo(ready bool) *v1.Silo {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "web3", UID: "u1"},
		Spec: v1.SiloSpec{Probes: &v1.Probes{Readiness: &v1.Probe{TCP: &v1.TCPProbe{Port: "rpc"}}},
			Ports:   []v1.SiloPort{{Name: "rpc", Port: 8545}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "rpc", HostPort: []string{v1.NetworkExternal}}}, RouteWhen: v1.RouteWhenReady}},
		Status: v1.SiloStatus{Phase: "Running", Host: "w1", SiloIP: "10.64.1.2"}}
	st := meta.ConditionFalse
	if ready {
		st = meta.ConditionTrue
	}
	meta.SetCondition(&s.Status.Conditions, meta.Condition{Type: "Ready", Status: st}, time.Now())
	return s
}

// The host's view marks a held silo, and its rules then have no outside rule for it.
func TestNetworkViewHeld(t *testing.T) {
	const dnat = "ip daddr 198.51.100.10 tcp dport 8545 dnat ip to 10.64.1.2:8545"
	for _, ready := range []bool{false, true} {
		view := NetworkView("w1", &v1.Host{Spec: v1.HostSpec{ExternalIP: "198.51.100.10"}}, []*v1.Silo{heldSilo(ready)}, nil, nil)
		if len(view.Local) != 1 || view.Local[0].Held == ready {
			t.Fatalf("ready %v: held %v", ready, view.Local[0].Held)
		}
		if got := strings.Contains(kni.Rules(view), dnat); got != ready {
			t.Fatalf("ready %v: outside rule %v", ready, got)
		}
	}
}

// The private name of a held silo exists with no record; a routed one answers.
func TestLookupHeld(t *testing.T) {
	q := names.Question{Name: "rpc.web3.kevaso", From: names.FromSilo}
	if a := names.Resolve(q, names.View{Silos: []*v1.Silo{heldSilo(false)}}); !a.InZone || !a.Found || len(a.IPs) != 0 {
		t.Fatalf("held: %+v", a)
	}
	if a := names.Resolve(q, names.View{Silos: []*v1.Silo{heldSilo(true)}}); len(a.IPs) != 1 || a.IPs[0].String() != "10.64.1.2" {
		t.Fatalf("routed: %+v", a)
	}
}
