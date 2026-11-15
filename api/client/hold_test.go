package client

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// A hold is entered by an answer below what was kept, whenever it was sent (K-071, K-097); once
// entered, it stays (K-107: TestK107ASameHistoryHoldNeverEndsByItself).
func TestAHoldIsEnteredBelowWhatWasKept(t *testing.T) {
	kept := Watermark{ClusterID: "c", History: "h", Epoch: 1, Revision: 26}
	if w, v := JudgeAnswer(kept, 26, ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: 25}); v != Hold || !w.Held {
		t.Fatalf("below what was kept: %v %+v, want Hold", v, w)
	}
	// Sent before anything was kept in this history (keptAtSend 0), lower than kept now: a slow
	// answer, not an older control plane (K-071).
	if w, v := JudgeAnswer(kept, 0, ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: 25}); v != Accept || w.Held || w.Revision != 26 {
		t.Fatalf("below what was kept, sent early: %v %+v, want Accept, keeping 26", v, w)
	}
	w, v := JudgeAnswer(kept, 26, ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: 26})
	if v != Accept || w.Held || w.Revision != 26 {
		t.Fatalf("at what was kept: %v %+v, want Accept", v, w)
	}
	if w, v = JudgeAnswer(w, 26, ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: 30}); v != Accept || w.Held || w.Revision != 30 {
		t.Fatalf("above: %v %+v", v, w)
	}
}

// After a restore (history h2, epoch 2) a system node that hasn't caught up still answers for
// history h1, epoch 1. That is a node of the same cluster lagging, not an older control plane:
// not yet (not applied, the client tries another node), never a hold.
func TestALaggingNodeIsNotYetNeverAHold(t *testing.T) {
	kept := Watermark{ClusterID: "c", History: "h2", Epoch: 2, Revision: 10}
	lagging := ControlPlaneSeen{ClusterID: "c", History: "h1", Epoch: 1, Revision: 900}
	w, v := JudgeStamp(kept, 10, lagging, true)
	if v != NotYet || w != kept {
		t.Fatalf("a lagging node: %v %+v, want NotYet and nothing changed", v, w)
	}
	// The same node once it has caught up: as usual.
	if w, v = JudgeStamp(kept, 10, ControlPlaneSeen{ClusterID: "c", History: "h2", Epoch: 2, Revision: 11}, true); v != Accept || w.Held {
		t.Fatalf("caught up: %v %+v", v, w)
	}
	// A judge from before NotYet (JudgeAnswer) holds on it, and, like any hold, keeps holding
	// until a new history or a person ends it (K-107).
	w, v = JudgeAnswer(kept, 10, lagging)
	if v != Hold || !w.Held {
		t.Fatalf("JudgeAnswer on a lagging node: %v %+v", v, w)
	}
	if w, v = JudgeAnswer(w, 10, ControlPlaneSeen{ClusterID: "c", History: "h2", Epoch: 2, Revision: 10}); v != Hold || !w.Held {
		t.Fatalf("an answer of the kept history after it: %v %+v, want still held", v, w)
	}
}

// An answer with no usable stamp (the store didn't give its revision) is not acted on by a
// worker that keeps a watermark.
func TestAnUnstampedAnswerIsNotYet(t *testing.T) {
	kept := Watermark{ClusterID: "c", History: "h", Epoch: 1, Revision: 10}
	if w, v := JudgeStamp(kept, 10, ControlPlaneSeen{}, false); v != NotYet || w != kept {
		t.Fatalf("unstamped: %v %+v", v, w)
	}
	if w, v := JudgeStamp(Watermark{}, 0, ControlPlaneSeen{}, false); v != Accept || w != (Watermark{}) {
		t.Fatalf("unstamped, nothing kept: %v %+v, want Accept, nothing kept", v, w)
	}
	// A revision of 0 is a stamp.
	h := http.Header{}
	SetControlPlane(h, ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: 0})
	if s, ok := ParseControlPlane(h); !ok || s.Revision != 0 {
		t.Fatalf("revision 0: %+v %v", s, ok)
	}
}

// verdicts is a judge that keeps a watermark in memory and gives its verdicts (ControlPlaneVerdicts).
type verdicts struct {
	mu   sync.Mutex
	kept Watermark
	got  []Verdict
}

func (j *verdicts) Sending() int64 { j.mu.Lock(); defer j.mu.Unlock(); return j.kept.Revision }
func (j *verdicts) Answer(sent int64, s ControlPlaneSeen) {
	j.Judged(sent, s, true)
}
func (j *verdicts) Judged(sent int64, s ControlPlaneSeen, stamped bool) Verdict {
	j.mu.Lock()
	defer j.mu.Unlock()
	var v Verdict
	j.kept, v = JudgeStamp(j.kept, sent, s, stamped)
	j.got = append(j.got, v)
	return v
}

// oldJudge is a judge from before ControlPlaneVerdicts.
type oldJudge struct{ answers atomic.Int32 }

func (*oldJudge) Sending() int64                   { return 0 }
func (j *oldJudge) Answer(int64, ControlPlaneSeen) { j.answers.Add(1) }
func stamp(w http.ResponseWriter, history string, epoch, rev int64) {
	SetControlPlane(w.Header(), ControlPlaneSeen{ClusterID: "c", History: history, Epoch: epoch, Revision: rev})
}

// The client never hands a caller an answer judged NotYet: a read goes to the next system node
// (and later requests start there); a write, which may have been applied, is not sent again but
// fails as NotYet. Without a judge nothing changes.
func TestTheClientNeverHandsOverANotYetAnswer(t *testing.T) {
	var lagHits, okHits atomic.Int32
	lagging := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lagHits.Add(1)
		stamp(w, "h1", 1, 900)
		_, _ = w.Write([]byte(`{"type":"user","name":"from-the-old-history"}`))
	}))
	defer lagging.Close()
	healthy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		okHits.Add(1)
		stamp(w, "h2", 2, 11)
		_, _ = w.Write([]byte(`{"type":"user","name":"ops"}`))
	}))
	defer healthy.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: lagging.Certificate().Raw})
	c, err := NewTLSEndpoints([]string{lagging.URL, healthy.URL}, ca, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	j := &verdicts{kept: Watermark{ClusterID: "c", History: "h2", Epoch: 2, Revision: 10}}
	c.ControlPlane = j
	ctx := context.Background()
	var who WhoAmI
	if err := c.Call(ctx, http.MethodGet, "/auth/whoami", nil, &who); err != nil || who.Name != "ops" {
		t.Fatalf("a read: %v %+v, want the healthy node's answer", err, who)
	}
	if lagHits.Load() != 1 || okHits.Load() != 1 {
		t.Fatalf("hits: lagging %d, healthy %d", lagHits.Load(), okHits.Load())
	}
	if err := c.Call(ctx, http.MethodGet, "/auth/whoami", nil, &who); err != nil || lagHits.Load() != 1 {
		t.Fatalf("the next read went back to the lagging node (%d hits): %v", lagHits.Load(), err)
	}
	if j.kept.Held {
		t.Fatalf("held by a lagging node: %+v", j.kept)
	}

	// A write answered NotYet: not sent again, and an error.
	c2, _ := NewTLSEndpoints([]string{lagging.URL, healthy.URL}, ca, nil, nil)
	c2.ControlPlane = &verdicts{kept: Watermark{ClusterID: "c", History: "h2", Epoch: 2, Revision: 10}}
	lag0, ok0 := lagHits.Load(), okHits.Load()
	who = WhoAmI{}
	err = c2.Call(ctx, http.MethodPost, "/auth/whoami", map[string]string{"a": "b"}, &who)
	if !IsNotYet(err) || who.Name != "" {
		t.Fatalf("a write answered by a lagging node: %v %+v, want NotYet and nothing read", err, who)
	}
	if lagHits.Load() != lag0+1 || okHits.Load() != ok0 {
		t.Fatalf("a write was sent twice: lagging %d, healthy %d", lagHits.Load()-lag0, okHits.Load()-ok0)
	}
	// …and the next request starts at the healthy node.
	if err := c2.Call(ctx, http.MethodGet, "/auth/whoami", nil, &who); err != nil || lagHits.Load() != lag0+1 {
		t.Fatalf("after a NotYet write: %v (lagging hits %d)", err, lagHits.Load()-lag0)
	}
}

// A judge from before ControlPlaneVerdicts still never gets an unstamped answer applied: the
// client calls it NotYet itself.
func TestAnUnstampedAnswerIsNotHandedOverToAnOldJudge(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"user","name":"unstamped"}`))
	}))
	defer ts.Close()
	c := New(ts.URL)
	j := &oldJudge{}
	c.ControlPlane = j
	var who WhoAmI
	err := c.Call(context.Background(), http.MethodGet, "/auth/whoami", nil, &who)
	var e *Error
	if !IsNotYet(err) || !errors.As(err, &e) || who.Name != "" || j.answers.Load() != 0 {
		t.Fatalf("unstamped, an old judge: %v %+v (%d answers)", err, who, j.answers.Load())
	}
	// No judge: as before.
	c.ControlPlane = nil
	if err := c.Call(context.Background(), http.MethodGet, "/auth/whoami", nil, &who); err != nil || who.Name != "unstamped" {
		t.Fatalf("no judge: %v %+v", err, who)
	}
}
