package apiserver_test

import (
	"net/http"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
)

// Rule 1: the control plane starts an opted-in silo elsewhere only once its host reported that
// its fence stopped it (FenceStopped). A non-host cannot add, change or remove that report
// (HostConditions). The silo's own host writes it only in its own name.
func TestANonHostCannotWriteThatAFenceStoppedTheSilo(t *testing.T) {
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, ns("dev"))
	for _, h := range []string{"hv1", "hv2"} {
		_ = e.admin.Create(e.ctx, host(h))
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Availability: v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop}}}
	if err := e.admin.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Running"
	if err := e.admin.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	worker := func(name string) *client.Client {
		tok, _ := e.tokens.Create(e.ctx, name, []string{"worker"}, time.Hour)
		cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, name, "worker")
		if err != nil {
			t.Fatal(err)
		}
		return e.tlsClient(t, &cred)
	}
	hv1, hv2 := worker("hv1"), worker("hv2")
	get := func() *v1.Silo {
		t.Helper()
		var x v1.Silo
		if err := e.admin.Get(e.ctx, "Silo", "dev", "db", &x); err != nil {
			t.Fatal(err)
		}
		return &x
	}
	stopped := func(by string) meta.Condition { return fence.StoppedCondition(by, nil, 1) }
	has := func(x *v1.Silo) *meta.Condition {
		return meta.FindCondition(x.Status.Conditions, fence.ConditionStopped)
	}

	// The admin socket (a person, a tool) forges hv1's report: kept as stored, so it isn't there.
	cur := get()
	cur.Status.Conditions = append(cur.Status.Conditions, stopped("hv1"))
	var warned []string
	e.admin.Warnings = func(w string) { warned = append(warned, w) }
	if err := e.admin.UpdateStatus(e.ctx, cur); err != nil {
		t.Fatalf("a status write by the admin socket: %v", err)
	}
	e.admin.Warnings = nil
	if x := get(); has(x) != nil {
		t.Fatalf("a non-host wrote FenceStopped: %+v", x.Status.Conditions)
	}
	if len(warned) == 0 {
		t.Error("the write was changed without a warning")
	}

	// Another host: refused, as any write of a silo not placed on it.
	cur = get()
	cur.Status.Conditions = append(cur.Status.Conditions, stopped("hv1"))
	if err := hv2.UpdateStatus(e.ctx, cur); code(err) != http.StatusForbidden {
		t.Fatalf("hv2 reporting hv1's silo stopped: %v, want 403", err)
	}
	// The silo's host, in another host's name: refused.
	cur = get()
	cur.Status.Conditions = append(cur.Status.Conditions, stopped("hv2"))
	if err := hv1.UpdateStatus(e.ctx, cur); code(err) != http.StatusForbidden {
		t.Fatalf("hv1 reporting a stop in hv2's name: %v, want 403", err)
	}
	// The silo's host, in its own name: written.
	cur = get()
	cur.Status.Conditions = append(cur.Status.Conditions, stopped("hv1"))
	if err := hv1.UpdateStatus(e.ctx, cur); err != nil {
		t.Fatalf("hv1 reporting its own fence stopped the silo: %v", err)
	}
	if x := get(); !fence.StoppedBy(x, "hv1", nil) {
		t.Fatalf("hv1's own report didn't land: %+v", x.Status.Conditions)
	}

	// A non-host taking it away, or changing it: put back as stored.
	cur = get()
	cur.Status.Conditions = nil
	if err := e.admin.UpdateStatus(e.ctx, cur); err != nil {
		t.Fatal(err)
	}
	if x := get(); !fence.StoppedBy(x, "hv1", nil) {
		t.Fatalf("a non-host removed FenceStopped: %+v", x.Status.Conditions)
	}
	cur = get()
	for i := range cur.Status.Conditions {
		if cur.Status.Conditions[i].Type == fence.ConditionStopped {
			cur.Status.Conditions[i].ObservedGeneration++
		}
	}
	if err := e.admin.UpdateStatus(e.ctx, cur); err != nil {
		t.Fatal(err)
	}
	if x := get(); !fence.StoppedBy(x, "hv1", nil) {
		t.Fatalf("a non-host changed FenceStopped: %+v", has(x))
	}

	// A placement change may drop the old report. It still cannot add one.
	cur = get()
	cur.Status.Host = "hv2"
	cur.Status.Conditions = nil
	if err := e.admin.UpdateStatus(e.ctx, cur); err != nil {
		t.Fatal(err)
	}
	if x := get(); has(x) != nil || x.Status.Host != "hv2" {
		t.Fatalf("placed elsewhere: host %s conditions %+v", x.Status.Host, x.Status.Conditions)
	}
	cur = get()
	cur.Status.Conditions = []meta.Condition{stopped("hv2")}
	if err := e.admin.UpdateStatus(e.ctx, cur); err != nil {
		t.Fatal(err)
	}
	if x := get(); has(x) != nil {
		t.Fatalf("a non-host added FenceStopped on the new placement: %+v", x.Status.Conditions)
	}
}
