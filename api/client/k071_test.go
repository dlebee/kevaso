package client

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// K-071: answers on one client aren't ordered. A slow answer made at revision 25 can arrive
// after a fast one made at 26: the control plane isn't older. Only an answer below what was kept
// when its request was SENT says so.
func TestAnAnswerIsJudgedAgainstWhatWasKeptWhenItWasSent(t *testing.T) {
	kept := Watermark{ClusterID: "c", History: "h", Epoch: 1, Revision: 26}
	slow := ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: 25}
	if w, v := JudgeAnswer(kept, 20, slow); v != Accept || w.Held || w.Revision != 26 {
		t.Fatalf("a slow answer sent when 20 was kept: %v %+v, want Accept and 26 kept", v, w)
	}
	if w, v := JudgeAnswer(kept, 26, slow); v != Hold || !w.Held {
		t.Fatalf("an answer below what was kept when it was sent: %v %+v, want Hold", v, w)
	}
	if _, v := Judge(kept, slow); v != Hold {
		t.Fatalf("Judge (sent now) of a lower revision: %v", v)
	}
}

type recorder struct {
	mu   sync.Mutex
	sent []int64
	got  []ControlPlaneSeen
	next int64
}

func (r *recorder) Sending() int64 { r.mu.Lock(); defer r.mu.Unlock(); r.next++; return r.next }
func (r *recorder) Answer(sent int64, s ControlPlaneSeen) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent, r.got = append(r.sent, sent), append(r.got, s)
}

// The client asks the judge before each request is sent and gives back, with the answer, what
// the judge said then.
func TestTheClientTellsTheJudgeWhenEachRequestWasSent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetControlPlane(w.Header(), ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: 7})
		if r.URL.Path == "/slow" {
			time.Sleep(100 * time.Millisecond)
		}
		_, _ = w.Write([]byte("{}"))
	}))
	defer ts.Close()
	rec := &recorder{}
	c := New(ts.URL)
	c.ControlPlane = rec
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = c.Call(t.Context(), http.MethodGet, "/slow", nil, nil) }()
	time.Sleep(30 * time.Millisecond)
	_ = c.Call(t.Context(), http.MethodGet, "/fast", nil, nil)
	wg.Wait()
	if len(rec.sent) != 2 || rec.sent[0] != 2 || rec.sent[1] != 1 || rec.got[0].Revision != 7 {
		t.Fatalf("sent %v: want the fast answer (sent second) first, then the slow one (sent first)", rec.sent)
	}
}
