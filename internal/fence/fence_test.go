package fence

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func silo(name, policy string) Silo {
	return Silo{ID: kri.ID{Namespace: "dev", Name: name, UID: "uid-" + name}, Runtime: "docker", OnHostLoss: policy}
}

func TestDecide(t *testing.T) {
	r := Record{LastContact: t0, Fence: true, Silos: []Silo{silo("wait", v1.OnHostLossWait), silo("recreate", v1.OnHostLossRecreate),
		silo("move", v1.OnHostLossMove), silo("unrecorded", "")}}
	names := func(ss []Silo) string {
		var n []string
		for _, s := range ss {
			n = append(n, s.ID.Name)
		}
		return strings.Join(n, ",")
	}
	// Within FenceAfter: nothing. An agent restart shorter than that fences nothing.
	if got := Decide(r, t0.Add(30*time.Second), 30*time.Second, nil); got != nil {
		t.Fatalf("at FenceAfter: %v", got)
	}
	// Past it: Recreate and Move, never Wait or a silo without a recorded policy.
	if got := names(Decide(r, t0.Add(31*time.Second), 30*time.Second, nil)); got != "move,recreate" {
		t.Fatalf("past FenceAfter: %s", got)
	}
	// Already stopped in this fence: not again.
	if got := names(Decide(r, t0.Add(time.Minute), 30*time.Second, map[string]bool{"uid-move": true})); got != "recreate" {
		t.Fatalf("after one stop: %s", got)
	}
	// Never in contact (a host that just joined): nothing here may run elsewhere.
	if got := Decide(Record{Fence: true, Silos: r.Silos}, t0.Add(time.Hour), 30*time.Second, nil); got != nil {
		t.Fatalf("never in contact: %v", got)
	}
	// A host nobody could start the silos elsewhere for (a one-node cluster): never.
	r.Fence = false
	if got := Decide(r, t0.Add(time.Hour), 30*time.Second, nil); got != nil {
		t.Fatalf("no fence applies: %v", got)
	}
}

// Whether a host needs a fence: wherever a second copy of its silos could be started while it
// may still run them.
func TestApplies(t *testing.T) {
	h := func(name string, cp, stateOnly, worker bool) v1.Host {
		var x v1.Host
		x.Name = name
		if cp {
			x.Spec.Components.ControlPlane = &v1.ControlPlaneSpec{StateOnly: stateOnly}
		}
		if worker {
			x.Spec.Components.Worker = &v1.WorkerSpec{}
		}
		return x
	}
	cpw := func(n string) v1.Host { return h(n, true, false, true) }
	cp := func(n string) v1.Host { return h(n, true, false, false) }
	light := func(n string) v1.Host { return h(n, true, true, false) }
	w := func(n string) v1.Host { return h(n, false, false, true) }
	for _, c := range []struct {
		name  string
		hosts []v1.Host
		self  string
		want  bool
	}{
		{"one node with a worker", []v1.Host{cpw("a")}, "a", false},
		{"one node with a worker, and worker hosts", []v1.Host{cpw("a"), w("b"), w("c")}, "a", false},
		{"a worker host", []v1.Host{cp("a"), w("b")}, "b", true},
		{"a worker host of a one-node cluster with a worker", []v1.Host{cpw("a"), w("b")}, "b", true},
		{"two system nodes: neither is a majority alone", []v1.Host{cpw("a"), cpw("b")}, "a", false},
		{"three system nodes with workers", []v1.Host{cpw("a"), cpw("b"), cpw("c")}, "a", true},
		{"three, the others without workers", []v1.Host{cpw("a"), cp("b"), cp("c")}, "a", true},
		{"two and a light node", []v1.Host{cpw("a"), cp("b"), light("c")}, "a", true},
		{"only light nodes besides: nobody serves the API", []v1.Host{cpw("a"), light("b"), light("c")}, "a", false},
		{"four, two down to two others", []v1.Host{cpw("a"), cpw("b"), cp("c"), cp("d")}, "a", true},
		{"a control plane without a worker", []v1.Host{cp("a"), cp("b"), cp("c")}, "a", false},
		{"not registered yet", []v1.Host{cp("a")}, "new", true},
	} {
		if got := Applies(c.hosts, c.self); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if r, err := Read(dir); err != nil || !r.LastContact.IsZero() {
		t.Fatalf("no record: %+v %v", r, err)
	}
	want := Record{LastContact: t0, Written: t0.Add(time.Second), Fence: true, Silos: []Silo{silo("a", v1.OnHostLossRecreate)}}
	if err := Write(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil || !got.LastContact.Equal(t0) || !got.Fence || len(got.Silos) != 1 || got.Silos[0] != want.Silos[0] {
		t.Fatalf("read back %+v %v", got, err)
	}
}

// The watcher, against a runtime: past FenceAfter it stops the Recreate silo once and leaves the
// Wait one running; when contact is back it forgets what it stopped.
func TestWatcher(t *testing.T) {
	ctx := context.Background()
	rt := fake.New()
	for _, s := range []Silo{silo("wait", v1.OnHostLossWait), silo("recreate", v1.OnHostLossRecreate)} {
		if err := rt.Create(ctx, kri.Spec{ID: s.ID}); err != nil {
			t.Fatal(err)
		}
		if err := rt.Start(ctx, s.ID); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	now := t0
	var logs []string
	w := &Watcher{Dir: dir, Runtimes: map[string]kri.Runtime{"docker": rt}, FenceAfter: 30 * time.Second,
		Now: func() time.Time { return now }, Log: func(f string, a ...any) { logs = append(logs, f) }}
	rec := Record{LastContact: t0, Fence: true, Silos: []Silo{silo("wait", v1.OnHostLossWait), silo("recreate", v1.OnHostLossRecreate)}}
	if err := Write(dir, rec); err != nil {
		t.Fatal(err)
	}
	state := func(name string) kri.State {
		st, _ := rt.Status(ctx, kri.ID{Namespace: "dev", Name: name, UID: "uid-" + name})
		return st.State
	}
	now = t0.Add(20 * time.Second)
	w.Check(ctx)
	if state("recreate") != kri.Running {
		t.Fatal("stopped within FenceAfter")
	}
	now = t0.Add(35 * time.Second)
	w.Check(ctx)
	if state("recreate") != kri.Stopped || state("wait") != kri.Running {
		t.Fatalf("past FenceAfter: recreate %s, wait %s", state("recreate"), state("wait"))
	}
	// Started again behind its back (it isn't, but say so): a fence stops each silo once.
	_ = rt.Start(ctx, kri.ID{Namespace: "dev", Name: "recreate", UID: "uid-recreate"})
	now = t0.Add(40 * time.Second)
	w.Check(ctx)
	if state("recreate") != kri.Running {
		t.Fatal("stopped twice in one fence")
	}
	// Contact back, then lost again: a new fence.
	rec.LastContact = t0.Add(45 * time.Second)
	_ = Write(dir, rec)
	now = t0.Add(50 * time.Second)
	w.Check(ctx)
	now = t0.Add(80 * time.Second)
	w.Check(ctx)
	if state("recreate") != kri.Stopped {
		t.Fatal("the second fence didn't stop it")
	}
	if len(logs) == 0 || !strings.Contains(strings.Join(logs, "\n"), "contact is back") {
		t.Errorf("logs: %v", logs)
	}
}

func TestUnit(t *testing.T) {
	u := Unit([]string{"cloud-hypervisor", "docker"}, 30*time.Second)
	for _, want := range []string{
		"ExecStart=/usr/local/bin/kevasod fence-watch --fence-after 30s --runtime cloud-hypervisor --runtime docker\n",
		"Restart=always\n", "WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	// Not tied to kevasod's unit: stopping kevasod must leave the fence running.
	for _, never := range []string{"PartOf=", "BindsTo=", "Requires=kevasod", "RuntimeDirectory="} {
		if strings.Contains(u, never) {
			t.Errorf("unit has %q:\n%s", never, u)
		}
	}
}

// A running silo with no record is a fault: the fence leaves it running (it may be a Wait silo),
// logs it loudly once, and leaves a report for the agent.
func TestWatcherReportsUnrecordedSilos(t *testing.T) {
	ctx := context.Background()
	rt := fake.New()
	stray := silo("stray", "")
	for _, s := range []Silo{silo("recreate", v1.OnHostLossRecreate), stray} {
		_ = rt.Create(ctx, kri.Spec{ID: s.ID})
		_ = rt.Start(ctx, s.ID)
	}
	dir := t.TempDir()
	now := t0
	var logs []string
	w := &Watcher{Dir: dir, Runtimes: map[string]kri.Runtime{"docker": rt}, FenceAfter: 30 * time.Second,
		Now: func() time.Time { return now }, Log: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	_ = Write(dir, Record{LastContact: t0, Fence: true, Silos: []Silo{silo("recreate", v1.OnHostLossRecreate)}})
	now = t0.Add(10 * time.Second)
	w.Check(ctx)
	if _, ok, _ := ReadFaults(dir); ok {
		t.Fatal("a report before any fence")
	}
	now = t0.Add(35 * time.Second)
	w.Check(ctx)
	now = t0.Add(36 * time.Second)
	w.Check(ctx)
	if st, _ := rt.Status(ctx, stray.ID); st.State != kri.Running {
		t.Fatalf("the unrecorded silo was stopped: %s", st.State)
	}
	f, ok, err := ReadFaults(dir)
	if err != nil || !ok || len(f.Silos) != 1 || f.Silos[0].ID.UID != stray.ID.UID || !f.At.Equal(t0.Add(35*time.Second)) {
		t.Fatalf("report: %+v %v %v", f, ok, err)
	}
	n := 0
	for _, l := range logs {
		if strings.Contains(l, "FAULT") && strings.Contains(l, "dev/stray") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("logged %d times:\n%s", n, strings.Join(logs, "\n"))
	}
}
