package agent_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

var cp1 = client.ControlPlaneSeen{ClusterID: "c1", History: "h1", Epoch: 1, Revision: 10}

// K-096 (review claim C): a watermark file that is there but empty, partial, or without a
// cluster (a power cut mid-write, `{}`, `{"held":true}`) is not "never seen a control plane": the
// worker holds, and the next answer doesn't replace it. Only a missing file is first contact.
func TestAWatermarkThatIsThereButSaysNothingHolds(t *testing.T) {
	for name, body := range map[string]string{"empty": "", "partial": `{"clusterID":"c1","hist`, "no cluster": `{}`, "held, no cluster": `{"held":true}`, "garbage": "\x00\x00"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "control-plane-watermark.json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			w := agent.OpenWatermark(p, t.Logf)
			if !w.Held() {
				t.Fatal("not held: the worker would trust whatever answers next")
			}
			w.Answer(w.Sending(), cp1)
			if !w.Held() {
				t.Fatal("an answer replaced an unreadable watermark: the hold is gone")
			}
			if b, _ := os.ReadFile(p); string(b) != body {
				t.Fatalf("the file was rewritten: %q", b)
			}
			if why := w.Unreadable(); why == "" {
				t.Fatal("Unreadable says nothing: nothing reports it")
			}
		})
	}
	w := agent.OpenWatermark(filepath.Join(t.TempDir(), "none.json"), t.Logf)
	if w.Held() || w.Unreadable() != "" {
		t.Fatal("a missing file is first contact")
	}
}

// K-096 (review claim C): what an answer raises is on disk before it counts. A watermark that
// can't be saved holds the worker (an answer acted on, then a restart with the older file, would
// accept a revision between the two), and the hold ends once a save succeeds.
func TestAnAnswerCountsOnlyOnceItsWatermarkIsSaved(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "wm", "control-plane-watermark.json")
	w := agent.OpenWatermark(p, t.Logf)
	if err := os.WriteFile(filepath.Join(dir, "wm"), []byte("a file where the folder goes"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Answer(w.Sending(), cp1)
	if !w.Held() {
		t.Fatal("acted on an answer whose watermark couldn't be saved")
	}
	if err := os.Remove(filepath.Join(dir, "wm")); err != nil {
		t.Fatal(err)
	}
	next := cp1
	next.Revision = 11
	w.Answer(w.Sending(), next)
	if w.Held() {
		t.Fatal("still held once the watermark could be saved")
	}
	again := agent.OpenWatermark(p, t.Logf)
	older := cp1
	older.Revision = 10
	again.Answer(again.Sending(), older)
	if !again.Held() {
		t.Fatal("after a restart, a revision below the one acted on was accepted: the file wasn't saved")
	}
}

// K-096: an unreadable watermark is never silent: the Host says so, with what to do, and the
// worker starts nothing meanwhile (it can't tell whether this control plane is an older one).
func TestAnUnreadableWatermarkIsReportedOnTheHost(t *testing.T) {
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
	if err := os.WriteFile(file, []byte(`{"clusterID":"c1","revi`), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := fake.New()
	cl := client.New(ts.URL)
	a := &agent.Agent{Client: cl, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}, WatermarkFile: file, Log: t.Logf}
	cl.ControlPlane = a.ControlPlaneJudge()
	agent.RunForTest(t, ctx, a)
	e := &env{c: c, ctx: ctx}
	e.place(t, "web", "hv1", nil)
	for {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", "hv1", &h); err != nil {
			t.Fatal(err)
		}
		if cond := meta.FindCondition(h.Status.Conditions, agent.ConditionControlPlaneBehind); cond != nil && cond.Status == meta.ConditionTrue {
			if cond.Reason != "WatermarkUnreadable" || !strings.Contains(cond.Message, "kvoadm host trust-control-plane") {
				t.Fatalf("the condition doesn't say what is wrong or what to do: %+v", cond)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("an unreadable watermark is never reported on the Host")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if calls := rt.CallLog(); len(calls) > 0 {
		t.Fatalf("started or changed something while it can't judge its control plane: %v", calls)
	}
}
