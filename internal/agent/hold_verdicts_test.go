package agent_test

import (
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/agent"
)

// The hold review, item 1 (host lane): the worker's watermark gives the client its verdicts
// (client.ControlPlaneVerdicts, judged with client.JudgeStamp), so an answer from a system node
// that hasn't caught up with a restore already accepted is NotYet (the client tries another node,
// nothing is applied, nothing held), and the client moves on from a node that answered Hold.
// Today the watermark only has Answer: such an answer holds (JudgeAnswer), until a healthy answer
// clears it.
func TestTheWatermarkGivesTheClientItsVerdicts(t *testing.T) {
	wm := agent.OpenWatermark("", nil)
	vj, ok := any(wm).(client.ControlPlaneVerdicts)
	if !ok {
		t.Fatal("agent.Watermark is not a client.ControlPlaneVerdicts")
	}
	if v := vj.Judged(wm.Sending(), client.ControlPlaneSeen{ClusterID: "c", History: "h2", Epoch: 2, Revision: 10}, true); v != client.Accept {
		t.Fatalf("first contact: %v", v)
	}
	if v := vj.Judged(wm.Sending(), client.ControlPlaneSeen{ClusterID: "c", History: "h1", Epoch: 1, Revision: 900}, true); v != client.NotYet || wm.Held() {
		t.Fatalf("a lagging node: %v, held %v; want NotYet, not held", v, wm.Held())
	}
	if v := vj.Judged(wm.Sending(), client.ControlPlaneSeen{}, false); v != client.NotYet || wm.Held() {
		t.Fatalf("unstamped: %v, held %v", v, wm.Held())
	}
}
