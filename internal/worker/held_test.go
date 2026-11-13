package worker

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
)

func heldSilo(ready bool) *v1.Silo {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "web3", UID: "u1"},
		Spec: v1.SiloSpec{Probes: &v1.Probes{Readiness: &v1.Probe{TCP: &v1.TCPProbe{Port: "rpc"}}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{{Name: "rpc", Port: 8545}}, Expose: v1.ExposeHostPort, RouteWhen: v1.RouteWhenReady}},
		Status: v1.SiloStatus{Phase: "Running", Host: "w1", Address: "10.64.1.2", Service: v1.SiloServiceStatus{PublicIP: "198.51.100.10"}}}
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
		view := NetworkView("w1", &v1.Host{Spec: v1.HostSpec{Address: "198.51.100.10"}}, []*v1.Silo{heldSilo(ready)}, nil)
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
	ip, inZone, found := Lookup("rpc.web3.kevaso", []*v1.Silo{heldSilo(false)})
	if !inZone || !found || ip.IsValid() {
		t.Fatalf("held: %v %v %v", ip, inZone, found)
	}
	if ip, _, found := Lookup("rpc.web3.kevaso", []*v1.Silo{heldSilo(true)}); !found || ip.String() != "10.64.1.2" {
		t.Fatalf("routed: %v %v", ip, found)
	}
}
