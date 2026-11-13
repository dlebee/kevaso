package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/moves"
)

// Design §0.3 through the API: admission refuses onHostLoss: Move on storage that can't move; a
// person moves a silo with create on silos/move; the old host must let go before the new one
// starts it, and only the old host can say it did; a lost host needs --confirm-fenced; a pinned
// silo and a target that can't take it are refused, saying why.
func TestMoves(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	worker := func(name string, runtimes ...string) {
		t.Helper()
		h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{ExternalIP: "203.0.113.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
		h.Status.Runtimes = map[string]v1.RuntimeStatus{}
		for _, r := range runtimes {
			h.Spec.Components.Worker.Runtimes = append(h.Spec.Components.Worker.Runtimes, v1.RuntimeSpec{Name: r})
			h.Status.Runtimes[r] = v1.RuntimeStatus{State: "Ready"}
		}
		if err := c.admin.Create(c.ctx, h); err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, Reason: "Heartbeat", LastTransitionTime: now}}
		h.Status.LastHeartbeat = &now
		h.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
		if err := c.admin.UpdateStatus(c.ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	worker("hv1", "docker", "cloud-hypervisor")
	worker("hv2", "docker")
	worker("hv3", "cloud-hypervisor")

	// Admission: Move on a microVM's local disk is refused, saying which disk.
	vm := silo("vm", "web3")
	vm.Spec.Availability.OnHostLoss = v1.OnHostLossMove
	if err := c.admin.Create(c.ctx, vm); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "disk root uses local") {
		t.Fatalf("Move on a local disk: %v", err)
	}
	// …and a Recreate silo with a host-local volume (a volume is kept data), naming it.
	rec := silo("rec", "web3")
	rec.Spec.Runtime = "docker"
	rec.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	rec.Spec.Volumes = []v1.Volume{{Name: "keys", MountPath: "/keys"}}
	if err := c.admin.Create(c.ctx, rec); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "leave volume keys behind") {
		t.Fatalf("Recreate leaving a local volume: %v", err)
	}
	rec.Spec.Volumes = nil

	place := func(s *v1.Silo, host string) *v1.Silo {
		t.Helper()
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host, s.Status.Phase = host, "Running"
		if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	web := silo("web", "web3")
	web.Spec.Runtime = "docker"
	place(web, "hv1")
	pinned := place(silo("pinned", "web3"), "hv1")
	place(rec, "hv1") // no volume: Recreate is fine

	c.bind(t, "ed", "ClusterRole", "editor")
	c.bind(t, "vi", "ClusterRole", "viewer")
	ed, vi := c.as(t, "ed"), c.as(t, "vi")
	mv := func(who *client.Client, name string, r moves.Request) (*v1.Silo, error) {
		var out v1.Silo
		err := who.Call(c.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/web3/silos/"+name+"/move", r, &out)
		return &out, err
	}

	if _, err := mv(vi, "web", moves.Request{To: "hv2"}); status(err) != http.StatusForbidden {
		t.Fatalf("viewer moved a silo: %v", err)
	}
	if _, err := mv(ed, "pinned", moves.Request{To: "hv3"}); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "disk root uses local on hv1") {
		t.Fatalf("pinned silo: %v", err)
	}
	if _, err := mv(ed, "web", moves.Request{To: "hv3"}); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "hv3 can't take it") {
		t.Fatalf("target without docker: %v", err)
	}
	if _, err := mv(ed, "web", moves.Request{To: "nowhere"}); status(err) != http.StatusUnprocessableEntity {
		t.Fatalf("unknown target: %v", err)
	}

	// kvo move --recreate: fine with no local volume, and a local one can't be added after.
	if fresh, err := mv(ed, "rec", moves.Request{To: "hv2", Recreate: true}); err != nil || fresh.Status.Host != "hv2" {
		t.Fatalf("--recreate without a local volume: %+v %v", fresh.Status, err)
	}
	var r2 v1.Silo
	_ = c.admin.Get(c.ctx, "Silo", "web3", "rec", &r2)
	r2.Spec.Volumes = append(r2.Spec.Volumes, v1.Volume{Name: "keys", MountPath: "/keys"})
	if err := c.admin.Update(c.ctx, &r2); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "leave volume keys behind") {
		t.Fatalf("adding a local volume to a Recreate silo: %v", err)
	}

	// The move: placed on hv2, hv1 lets go first.
	moved, err := mv(ed, "web", moves.Request{To: "hv2"})
	if err != nil || moved.Status.Host != "hv2" || moved.Status.MovingFrom != "hv1" || !meta.IsTrue(moved.Status.Conditions, "Moved") {
		t.Fatalf("move: %+v %v", moved.Status, err)
	}
	if _, err := mv(ed, "web", moves.Request{To: "hv1"}); status(err) != http.StatusConflict {
		t.Fatalf("a second move during the first: %v", err)
	}
	// hv2 (the new host) can't clear the handoff; hv1 can, and nothing else.
	hv1, hv2 := c.host(t, "hv1"), c.host(t, "hv2")
	var cur v1.Silo
	get := func() {
		t.Helper()
		if err := c.admin.Get(c.ctx, "Silo", "web3", "web", &cur); err != nil {
			t.Fatal(err)
		}
	}
	get()
	cur.Status.MovingFrom = ""
	if err := hv2.UpdateStatus(c.ctx, &cur); status(err) != http.StatusForbidden {
		t.Fatalf("the new host cleared the handoff: %v", err)
	}
	get()
	cur.Status.MovingFrom, cur.Status.Phase = "", "Running"
	if err := hv1.UpdateStatus(c.ctx, &cur); status(err) != http.StatusForbidden {
		t.Fatalf("the old host changed more than the handoff: %v", err)
	}
	get()
	cur.Status.MovingFrom = ""
	if err := hv1.UpdateStatus(c.ctx, &cur); err != nil {
		t.Fatalf("the old host letting go: %v", err)
	}
	get()
	if cur.Status.MovingFrom != "" || !moves.MayStart(&cur, "hv2") {
		t.Fatalf("after the handoff: %+v", cur.Status)
	}

	// With a volume: hv1 first unmounts it (its one other write during the handoff), then lets
	// go. A write from a stale copy is a conflict, not a refusal. This is the agent's order on a
	// real host (E2E: the unmount was refused, so the volume never left hv1).
	place(silo("vol", "web3"), "hv1")
	get2 := func() *v1.Silo {
		t.Helper()
		var x v1.Silo
		if err := c.admin.Get(c.ctx, "Silo", "web3", "vol", &x); err != nil {
			t.Fatal(err)
		}
		return &x
	}
	vol := get2()
	vol.Status.Host, vol.Status.MovingFrom = "hv2", "hv1"
	vol.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: "linode-block", Handle: "7", AttachedTo: "hv1", Mounted: true}}
	if err := c.admin.UpdateStatus(c.ctx, vol); err != nil {
		t.Fatal(err)
	}
	stale := get2()
	vol = get2()
	vol.Status.Volumes[0].Mounted = false
	vol.Status.Phase = "Stopped"
	if err := hv1.UpdateStatus(c.ctx, vol); status(err) != http.StatusForbidden {
		t.Fatalf("the old host changed more than unmounting: %v", err)
	}
	vol = get2()
	vol.Status.Volumes[0].Mounted = false
	if err := hv1.UpdateStatus(c.ctx, vol); err != nil {
		t.Fatalf("the old host unmounting its volume during the handoff: %v", err)
	}
	stale.Status.MovingFrom = ""
	stale.Status.Volumes[0].Mounted = false
	if err := hv1.UpdateStatus(c.ctx, stale); status(err) != http.StatusConflict {
		t.Fatalf("letting go from a stale copy: %v, want a conflict", err)
	}
	vol = get2()
	if vol.Status.Volumes[0].Mounted || vol.Status.MovingFrom != "hv1" {
		t.Fatalf("after unmounting: %+v", vol.Status)
	}
	vol.Status.MovingFrom = ""
	if err := hv1.UpdateStatus(c.ctx, vol); err != nil {
		t.Fatalf("the old host letting go after unmounting: %v", err)
	}
	if vol = get2(); vol.Status.MovingFrom != "" || !moves.MayStart(vol, "hv2") {
		t.Fatalf("after the handoff: %+v", vol.Status)
	}

	// hv2 is lost: moving back needs --confirm-fenced, and then there's no handoff to wait for.
	var h v1.Host
	_ = c.admin.Get(c.ctx, "Host", "", "hv2", &h)
	h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionUnknown, Reason: "HostLost", LastTransitionTime: time.Now()}}
	if err := c.admin.UpdateStatus(c.ctx, &h); err != nil {
		t.Fatal(err)
	}
	if _, err := mv(ed, "web", moves.Request{To: "hv1"}); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "--confirm-fenced") {
		t.Fatalf("from a lost host, unconfirmed: %v", err)
	}
	back, err := mv(ed, "web", moves.Request{To: "hv1", ConfirmFenced: true})
	if err != nil || back.Status.Host != "hv1" || back.Status.MovingFrom != "" {
		t.Fatalf("confirmed: %+v %v", back.Status, err)
	}
	_ = pinned
}
