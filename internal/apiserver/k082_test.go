package apiserver_test

import (
	"net/http"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/moves"
)

// K-082: StartClaim and FenceArmed are the silo's own host's to write. A forged "armed" let the
// control plane restart an opted-in silo elsewhere while its host never armed its fence; a forged
// claim kept a host counted as in contact. Anyone else who writes the silo's status (a person with
// update on silos/status, the admin socket, a controller) has those two conditions kept as stored,
// with a warning; another host is refused (it writes only silos placed on it); the silo's host
// writes them only in its own name. A placement change may drop them (they were the old
// placement's), never add or change them.
func TestK082OnlyTheSilosHostWritesItsClaimAndItsFence(t *testing.T) {
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, ns("dev"))
	for _, h := range []string{"hv1", "hv2", "hv3"} {
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
	now := time.Now().UTC()
	armed := func(h string, gen int64) meta.Condition { return fence.ArmedCondition(h, 2*time.Minute, gen) }
	claim := func(h string) meta.Condition {
		return meta.Condition{Type: moves.CondStartClaim, Status: meta.ConditionTrue, Reason: "Starting", Message: "starting on " + h + " at " + now.Format(time.RFC3339Nano)}
	}
	has := func(x *v1.Silo, typ string) *meta.Condition { return meta.FindCondition(x.Status.Conditions, typ) }

	// The admin socket (a person, a tool) forges hv1's armed fence and claim: kept as stored.
	cur := get()
	cur.Status.Conditions = append(cur.Status.Conditions, armed("hv1", cur.Generation), claim("hv1"))
	var warned []string
	e.admin.Warnings = func(w string) { warned = append(warned, w) }
	if err := e.admin.UpdateStatus(e.ctx, cur); err != nil {
		t.Fatalf("a status write by the admin socket: %v", err)
	}
	e.admin.Warnings = nil
	if x := get(); has(x, fence.ConditionArmed) != nil || has(x, moves.CondStartClaim) != nil {
		t.Fatalf("a non-host wrote the host's conditions: %+v", x.Status.Conditions)
	}
	if len(warned) == 0 {
		t.Error("the write was changed without a warning")
	}
	if fence.Armed(get()) {
		t.Fatal("the forged armed fence counts")
	}

	// Another host: refused, as any write of a silo not placed on it.
	cur = get()
	cur.Status.Conditions = append(cur.Status.Conditions, armed("hv1", cur.Generation))
	if err := hv2.UpdateStatus(e.ctx, cur); code(err) != http.StatusForbidden {
		t.Fatalf("hv2 arming hv1's silo: %v, want 403", err)
	}
	// The silo's host, in another host's name: refused.
	cur = get()
	cur.Status.Conditions = append(cur.Status.Conditions, armed("hv2", cur.Generation))
	if err := hv1.UpdateStatus(e.ctx, cur); code(err) != http.StatusForbidden {
		t.Fatalf("hv1 arming in hv2's name: %v, want 403", err)
	}
	// The silo's host, in its own name: written.
	cur = get()
	cur.Status.Conditions = append(cur.Status.Conditions, armed("hv1", cur.Generation), claim("hv1"))
	if err := hv1.UpdateStatus(e.ctx, cur); err != nil {
		t.Fatalf("hv1 arming its own silo: %v", err)
	}
	if x := get(); !fence.Armed(x) || has(x, moves.CondStartClaim) == nil {
		t.Fatalf("hv1's own conditions didn't land: %+v", x.Status.Conditions)
	}

	// A non-host taking them away, or changing them: put back as stored.
	cur = get()
	cur.Status.Conditions = nil
	if err := e.admin.UpdateStatus(e.ctx, cur); err != nil {
		t.Fatal(err)
	}
	if x := get(); !fence.Armed(x) || has(x, moves.CondStartClaim) == nil {
		t.Fatalf("a non-host removed hv1's conditions: %+v", x.Status.Conditions)
	}
	cur = get()
	for i := range cur.Status.Conditions {
		if cur.Status.Conditions[i].Type == fence.ConditionArmed {
			cur.Status.Conditions[i].ObservedGeneration++
		}
	}
	if err := e.admin.UpdateStatus(e.ctx, cur); err != nil {
		t.Fatal(err)
	}
	if x := get(); !fence.Armed(x) {
		t.Fatalf("a non-host changed hv1's armed condition: %+v", has(x, fence.ConditionArmed))
	}

	// A placement change (the silo controller's, a tool's) may drop them with the old placement.
	cur = get()
	cur.Status.Host = "hv3"
	cur.Status.Conditions = slicesDelete(cur.Status.Conditions, moves.CondStartClaim)
	if err := e.admin.UpdateStatus(e.ctx, cur); err != nil {
		t.Fatal(err)
	}
	if x := get(); has(x, moves.CondStartClaim) != nil || !hasArmedFor(x, "hv1") {
		t.Fatalf("placed elsewhere: the old claim should be gone and the old armed kept as written: %+v", x.Status.Conditions)
	}
}

func slicesDelete(conds []meta.Condition, typ string) []meta.Condition {
	var out []meta.Condition
	for _, c := range conds {
		if c.Type != typ {
			out = append(out, c)
		}
	}
	return out
}

func hasArmedFor(s *v1.Silo, host string) bool {
	c := meta.FindCondition(s.Status.Conditions, fence.ConditionArmed)
	return c != nil && c.Message == fence.ArmedCondition(host, 2*time.Minute, 0).Message
}
