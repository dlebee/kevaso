package agent_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controllers/restore"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// holdStop is hv1's runtime. Once hold is set, Stop waits until letGo, so the test can see
// the chosen host's behaviour while this copy is still running.
type holdStop struct {
	*fake.Runtime
	hold    atomic.Bool
	release chan struct{}
	entered chan struct{}
	let     sync.Once
	enter   sync.Once
}

func newHoldStop(rt *fake.Runtime) *holdStop {
	return &holdStop{Runtime: rt, release: make(chan struct{}), entered: make(chan struct{})}
}

func (h *holdStop) Stop(ctx context.Context, id kri.ID) error {
	if h.hold.Load() {
		h.enter.Do(func() { close(h.entered) })
		select {
		case <-h.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return h.Runtime.Stop(ctx, id)
}

func (h *holdStop) letGo() { h.let.Do(func() { close(h.release) }) }

// A holder that is still running blocks the chosen host. When that copy stops, the silo
// starts there. Nothing on the path deletes a disk.
func TestAHolderStillRunningBlocksTheStart(t *testing.T) {
	w := newSettleWorld(t, true)
	w.freeze()
	w.startController()
	w.hold.hold.Store(true)
	t.Cleanup(w.hold.letGo)
	out := w.settle()
	if out.Status.Restore == nil || out.Status.Restore.Phase != v1.RestoreFrozen || out.Status.Restore.SettlingTo != "hv2" || out.Status.MovingFrom != "" {
		t.Fatalf("placement: phase %s settling %q movingFrom %q", phaseOf(out), settlingOf(out), out.Status.MovingFrom)
	}
	select {
	case <-w.hold.entered:
	case <-w.ctx.Done():
		t.Fatal("hv1 did not stop its copy after the silo was placed on hv2")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if w.state(w.hv2) == kri.Running {
			t.Fatalf("hv2 started while hv1's copy was still running (phase %s)", phaseOf(w.silo()))
		}
		if w.state(w.hv1rt) != kri.Running {
			t.Fatal("hv1's copy stopped before the hold was released")
		}
		if w.deleted(w.hv1) || w.deleted(w.hv2) {
			t.Fatalf("a disk was removed while the other copy was still running: hv1 %v hv2 %v", w.hv1.CallLog(), w.hv2.CallLog())
		}
		time.Sleep(20 * time.Millisecond)
	}
	w.hold.letGo()
	w.wait("hv1 stopped and kept", func() bool {
		st := w.state(w.hv1rt)
		return st != kri.Running && st != kri.Absent
	})
	w.wait("settled and running on hv2", func() bool {
		s := w.silo()
		return s.Status.Restore != nil && s.Status.Restore.Phase == v1.RestoreSettled && s.Status.Host == "hv2" && w.state(w.hv2) == kri.Running
	})
	w.keptDisks()
}

// A holder that was cut off after it reported keeps the silo from starting on the chosen
// host until that holder is confirmed off. Its disk stays.
func TestACutOffHolderBlocksUntilItIsConfirmedOff(t *testing.T) {
	w := newSettleWorld(t, false)
	w.report("hv1", true)
	w.freeze()
	w.startController()
	out := w.settle()
	if out.Status.Restore == nil || out.Status.Restore.Phase != v1.RestoreFrozen || out.Status.Host != "hv2" {
		t.Fatalf("placement: %+v", out.Status)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s := w.silo()
		if w.state(w.hv2) == kri.Running || (s.Status.Restore != nil && s.Status.Restore.Phase == v1.RestoreSettled) {
			t.Fatalf("a cut-off holder did not block the start: phase %s hv2 %s", phaseOf(s), w.state(w.hv2))
		}
		time.Sleep(20 * time.Millisecond)
	}
	var g v1.RestoreGate
	if err := w.c.Get(w.ctx, "RestoreGate", "", v1.RestoreGateName, &g); err != nil {
		t.Fatal(err)
	}
	g.Spec.ConfirmedOff = append(g.Spec.ConfirmedOff, "hv1")
	if err := w.c.Update(w.ctx, &g); err != nil {
		t.Fatal(err)
	}
	w.wait("settled once hv1 is confirmed off", func() bool {
		s := w.silo()
		return s.Status.Restore != nil && s.Status.Restore.Phase == v1.RestoreSettled && s.Status.Host == "hv2" && w.state(w.hv2) == kri.Running
	})
	if w.state(w.hv1rt) != kri.Running {
		t.Fatalf("the cut-off host's copy is gone: %s", w.state(w.hv1rt))
	}
	w.keptDisks()
}

type settleWorld struct {
	t     *testing.T
	ctx   context.Context
	c     *client.Client
	id    kri.ID
	hv1   *fake.Runtime
	hv1rt kri.Runtime
	hv2   *fake.Runtime
	hold  *holdStop
}

func newSettleWorld(t *testing.T, hv1Agent bool) *settleWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	cp := &cpHeaders{h: srv, seen: client.ControlPlaneSeen{ClusterID: "c1", History: "h2", Epoch: 2, Revision: 10}}
	ts := httptest.NewServer(cp)
	t.Cleanup(ts.Close)
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hv1", "hv2"} {
		if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{InternalIP: "10.0.0." + name[len(name)-1:], Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
			t.Fatal(err)
		}
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", VM: &v1.VMSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, &v1.RestoreGate{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RestoreGate"}, ObjectMeta: meta.ObjectMeta{Name: v1.RestoreGateName},
		Spec: v1.RestoreGateSpec{History: "h2", Started: time.Now().Add(time.Hour), NoHostsAdded: true, Required: []string{"hv1", "hv2"}}}); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Running"
	s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Handle: "vol-1", AttachedTo: "hv1", Mounted: true}}
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	id := kri.ID{Namespace: "dev", Name: "web", UID: s.UID}
	hv1 := fake.New()
	hv2 := fake.New()
	hold := newHoldStop(hv1)
	w := &settleWorld{t: t, ctx: ctx, c: c, id: id, hv1: hv1, hv1rt: hold, hv2: hv2, hold: hold}
	if err := hold.Create(ctx, kri.Spec{ID: id, Image: "ubuntu-24.04", CPU: 1, Memory: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	if err := hold.Start(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := hv2.Create(ctx, kri.Spec{ID: id, Image: "ubuntu-24.04", CPU: 1, Memory: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	if hv1Agent {
		startSettleAgent(t, ctx, ts.URL, "hv1", hold)
		w.wait("hv1 reported its copy running", func() bool { return w.reported("hv1", true) })
	}
	startSettleAgent(t, ctx, ts.URL, "hv2", hv2)
	w.wait("hv2 reported its copy stopped", func() bool { return w.reported("hv2", false) })
	t.Cleanup(cancel)
	return w
}

func startSettleAgent(t *testing.T, ctx context.Context, url, host string, rt kri.Runtime) {
	t.Helper()
	cl := client.New(url)
	a := &agent.Agent{Client: cl, HostName: host, Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}, Log: t.Logf}
	cl.ControlPlane = a.ControlPlaneJudge()
	agent.RunForTest(t, ctx, a)
}

func (w *settleWorld) startController() {
	w.t.Helper()
	silos, hosts, gates := informer.New(w.c, "Silo"), informer.New(w.c, "Host"), informer.New(w.c, "RestoreGate")
	ctrl := &restore.Controller{Client: w.c, Silos: silos, Hosts: hosts, Gates: gates}
	e := engine.New(clock.Real{})
	e.Register(ctrl, engine.Options{Workers: 1})
	e.WaitFor(silos, hosts, gates)
	silos.AddHandler(func(k informer.Key) {
		e.Changed(engine.Key{Kind: "Silo", Namespace: k.Namespace, Name: k.Name})
	})
	hosts.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Host", Name: k.Name}) })
	gates.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "RestoreGate", Name: k.Name}) })
	go func() {
		silos.Run(w.ctx)
	}()
	go func() {
		hosts.Run(w.ctx)
	}()
	go func() {
		gates.Run(w.ctx)
	}()
	go func() {
		e.Run(w.ctx)
	}()
	if !silos.WaitSynced(w.ctx) || !hosts.WaitSynced(w.ctx) || !gates.WaitSynced(w.ctx) {
		w.t.Fatal("restore caches did not sync")
	}
}

func (w *settleWorld) freeze() {
	w.t.Helper()
	for range 8 {
		var s v1.Silo
		if err := w.c.Get(w.ctx, "Silo", "dev", "web", &s); err != nil {
			w.t.Fatal(err)
		}
		s.Status.Restore = &v1.SiloRestore{History: "h2", Phase: v1.RestoreFrozen, Holders: []string{"hv1", "hv2"}}
		if !hasHandle(s.Status.Volumes, "vol-1") {
			s.Status.Volumes = append(s.Status.Volumes, v1.VolumeStatus{Name: "data", Handle: "vol-1", AttachedTo: "hv1", Mounted: true})
		}
		err := w.c.UpdateStatus(w.ctx, &s)
		if err == nil {
			return
		}
		if !client.IsConflict(err) {
			w.t.Fatal(err)
		}
	}
	w.t.Fatal("could not freeze the silo")
}

func (w *settleWorld) report(host string, running bool) {
	w.t.Helper()
	for range 5 {
		var h v1.Host
		if err := w.c.Get(w.ctx, "Host", "", host, &h); err != nil {
			w.t.Fatal(err)
		}
		h.Status.Copies = &v1.HostCopies{History: "h2", Reported: true, Held: []v1.HostHeldCopy{{
			Namespace: "dev", Name: "web", UID: w.id.UID, Running: running,
		}}}
		err := w.c.UpdateStatus(w.ctx, &h)
		if err == nil {
			return
		}
		if !client.IsConflict(err) {
			w.t.Fatal(err)
		}
	}
	w.t.Fatal("could not report")
}

func (w *settleWorld) settle() v1.Silo {
	w.t.Helper()
	var out v1.Silo
	var err error
	for range 5 {
		err = w.c.Call(w.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/web/restore-settle", map[string]string{"to": "hv2"}, &out)
		if err == nil || !client.IsConflict(err) {
			break
		}
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return out
}

func (w *settleWorld) silo() v1.Silo {
	w.t.Helper()
	var s v1.Silo
	if err := w.c.Get(w.ctx, "Silo", "dev", "web", &s); err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *settleWorld) reported(host string, running bool) bool {
	var h v1.Host
	if err := w.c.Get(w.ctx, "Host", "", host, &h); err != nil || h.Status.Copies == nil || h.Status.Copies.History != "h2" {
		return false
	}
	for _, c := range h.Status.Copies.Held {
		if c.UID == w.id.UID {
			return c.Running == running
		}
	}
	return false
}

func (w *settleWorld) state(rt kri.Runtime) kri.State {
	st, err := rt.Status(w.ctx, w.id)
	if err != nil {
		return kri.Absent
	}
	return st.State
}

func (w *settleWorld) deleted(rt *fake.Runtime) bool {
	for _, c := range rt.CallLog() {
		if strings.HasPrefix(c, "delete ") {
			return true
		}
	}
	return false
}

func (w *settleWorld) keptDisks() {
	w.t.Helper()
	if w.deleted(w.hv1) || w.deleted(w.hv2) {
		w.t.Fatalf("a disk was removed: hv1 %v hv2 %v", w.hv1.CallLog(), w.hv2.CallLog())
	}
	s := w.silo()
	if !hasHandle(s.Status.Volumes, "vol-1") {
		w.t.Fatalf("the volume was destroyed: %+v", s.Status.Volumes)
	}
	if w.state(w.hv1rt) == kri.Absent || w.state(w.hv2) == kri.Absent {
		w.t.Fatalf("a copy is gone: hv1 %s hv2 %s", w.state(w.hv1rt), w.state(w.hv2))
	}
}

func (w *settleWorld) wait(what string, ok func() bool) {
	w.t.Helper()
	for {
		if ok() {
			return
		}
		select {
		case <-w.ctx.Done():
			s := w.silo()
			w.t.Fatalf("timed out waiting for %s: phase %s host %s hv1 %s hv2 %s\nhv1 %v\nhv2 %v",
				what, phaseOf(s), s.Status.Host, w.state(w.hv1rt), w.state(w.hv2), w.hv1.CallLog(), w.hv2.CallLog())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func hasHandle(vols []v1.VolumeStatus, handle string) bool {
	for _, v := range vols {
		if v.Handle == handle {
			return true
		}
	}
	return false
}

func phaseOf(s v1.Silo) string {
	if s.Status.Restore == nil {
		return ""
	}
	return s.Status.Restore.Phase
}

func settlingOf(s v1.Silo) string {
	if s.Status.Restore == nil {
		return ""
	}
	return s.Status.Restore.SettlingTo
}
