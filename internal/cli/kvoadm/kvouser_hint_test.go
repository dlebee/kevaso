package kvoadm

import "testing"

// kvoadm init printed "kvoadm users resign root@ADDRESS … --kvo" for renewing kvo's certificate:
// wrong where root can't log in over SSH (found installing from the docs on a machine reached as
// ubuntu). kvoadm knows the system node's name; the admin hint already used it.
func TestKvoRenewHintUsesTheSystemNodesName(t *testing.T) {
	if got := KvoRenewHint("hv1", "ana", "https://203.0.113.10:6443"); got != "kvoadm users resign hv1 --name ana --kvo" {
		t.Fatalf("by name: %q", got)
	}
	if got := KvoRenewHint("ubuntu@203.0.113.10", "ana", "https://203.0.113.10:6443"); got != "kvoadm users resign ubuntu@203.0.113.10 --name ana --kvo" {
		t.Fatalf("as typed: %q", got)
	}
	if got := KvoRenewHint("", "ana", "https://203.0.113.10:6443"); got != "kvoadm users resign root@203.0.113.10 --name ana --kvo" {
		t.Fatalf("no target: kvo's own hint: %q", got)
	}
}
