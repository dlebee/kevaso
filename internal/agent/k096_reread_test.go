package agent_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// Review claim 5 (K-096): a read of the watermark that failed once at start (a transient error:
// here the path is briefly a folder) held the worker for the life of the process, and kvoadm host
// trust-control-plane refuses a file that reads fine. The agent reads the file again while it
// holds for it; once it reads and holds a watermark of a cluster, the hold ends by itself, the
// Host says so, and the answers are judged against what the file says.
func TestAWatermarkUnreadableOnlyAtStartIsReadAgain(t *testing.T) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	cp := &cpHeaders{h: srv, seen: cp1}
	ts := httptest.NewServer(cp)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "control-plane-watermark.json")
	if err := os.Mkdir(file, 0o700); err != nil { // read fails: "is a directory"
		t.Fatal(err)
	}
	rt := fake.New()
	cl := client.New(ts.URL)
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	a := &agent.Agent{Client: cl, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clk, WatermarkFile: file, Log: t.Logf}
	cl.ControlPlane = a.ControlPlaneJudge()
	if !a.ControlPlaneHeld() {
		t.Fatal("not held although the watermark couldn't be read")
	}
	agent.RunForTest(t, ctx, a)
	e := &env{c: c, ctx: ctx}
	e.place(t, "web", "hv1", nil)

	condition := func() *meta.Condition {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", "hv1", &h); err != nil {
			t.Fatal(err)
		}
		return meta.FindCondition(h.Status.Conditions, agent.ConditionControlPlaneBehind)
	}
	until := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !ok(); {
			if time.Now().After(deadline) {
				t.Fatalf("never: %s", what)
			}
			clk.Step(fence.CheckEvery)
			time.Sleep(5 * time.Millisecond)
		}
	}
	until("the Host says the watermark is unreadable", func() bool {
		cond := condition()
		return cond != nil && cond.Status == meta.ConditionTrue && cond.Reason == "WatermarkUnreadable"
	})
	if calls := rt.CallLog(); len(calls) > 0 {
		t.Fatalf("changed something while held: %v", calls)
	}

	// The read error passes: the file is there and holds this worker's watermark.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(`{"clusterID":"c1","history":"h1","epoch":1,"revision":5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	until("the hold ends once the file reads", func() bool { return !a.ControlPlaneHeld() })
	until("the Host says the control plane is trusted", func() bool {
		cond := condition()
		return cond != nil && cond.Status == meta.ConditionFalse
	})
	until("the silo starts", func() bool {
		for _, c := range rt.CallLog() {
			if c == "start dev/web" {
				return true
			}
		}
		return false
	})
}

// A file that reads but says less than before is still judged: a watermark whose revision is
// above what the control plane answers is a hold (Held), not trust, after the re-read too.
func TestAWatermarkReadAgainIsJudgedAsAtStart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "control-plane-watermark.json")
	if err := os.Mkdir(file, 0o700); err != nil {
		t.Fatal(err)
	}
	w := agent.OpenWatermark(file, t.Logf)
	if !w.Held() {
		t.Fatal("not held")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(`{"clusterID":"c1","history":"h1","epoch":1,"revision":50}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !w.ReadAgain() || w.Unreadable() != "" {
		t.Fatalf("not read again: %q", w.Unreadable())
	}
	w.Answer(w.Sending(), cp1) // revision 10, below the 50 kept
	if !w.Held() {
		t.Fatal("an older control plane was trusted after the re-read")
	}
}

// An answer to a request sent while the file couldn't be read is judged against nothing it can
// trust: after the re-read it counts as NotYet (the client asks again), never as an acceptance.
func TestAnAnswerSentWhileUnreadableIsNotJudgedAfterTheReRead(t *testing.T) {
	file := filepath.Join(t.TempDir(), "control-plane-watermark.json")
	if err := os.Mkdir(file, 0o700); err != nil {
		t.Fatal(err)
	}
	w := agent.OpenWatermark(file, t.Logf)
	sent := w.Sending() // a request leaves while the file can't be read
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(`{"clusterID":"c1","history":"h1","epoch":1,"revision":50}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !w.ReadAgain() {
		t.Fatal("not read again")
	}
	if v := w.Judged(sent, cp1, true); v != client.NotYet {
		t.Fatalf("an answer sent while the file couldn't be read, revision 10 below the 50 kept: %s", v)
	}
	if v := w.Judged(w.Sending(), cp1, true); v != client.Hold {
		t.Fatalf("the same answer to a request sent now: %s, want Hold", v)
	}
}
