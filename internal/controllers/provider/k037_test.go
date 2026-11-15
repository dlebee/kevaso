package provider_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controllers/provider"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

type k037 struct {
	ctx   context.Context
	t     *testing.T
	st    store.Store
	c     *client.Client
	fake  *kplugintest.Fake
	reg   *plugins.Registry
	known *provider.Providers
}

func newK037(t *testing.T) *k037 {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	dir, _ := os.MkdirTemp("/tmp", "kvp")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	x := &k037{ctx: ctx, t: t, st: st, c: client.New(ts.URL), fake: kplugintest.New(), reg: &plugins.Registry{Dir: filepath.Join(dir, "plugins")}, known: &provider.Providers{}}
	x.must(x.reg.Add(ctx, x.fake))
	x.must(x.c.Create(ctx, &v1.Namespace{TypeMeta: tm037("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	for i, n := range []string{"w1", "w2"} {
		ip := "10.0.0." + string(rune('1'+i))
		x.fake.Machines[ip] = kplugin.HostInfo{ID: string(rune('1' + i)), Region: "r", PrivateAddress: "192.168.0." + string(rune('1'+i))}
		h := &v1.Host{TypeMeta: tm037("Host"), ObjectMeta: meta.ObjectMeta{Name: n},
			Spec: v1.HostSpec{InternalIP: ip, Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		x.must(x.c.Create(ctx, h))
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, LastTransitionTime: time.Now().UTC().Truncate(time.Second)}}
		x.must(x.c.UpdateStatus(ctx, h))
	}
	// The control plane's provider-hosts controller describes them.
	hosts := &provider.Hosts{Client: x.c, Hosts: x.frozen("Host"), Plugins: x.reg, Providers: x.known}
	for _, n := range []string{"w1", "w2"} {
		if _, err := hosts.Reconcile(ctx, engine.Key{Kind: "Host", Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	return x
}

func tm037(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }

func (x *k037) must(err error) {
	x.t.Helper()
	if err != nil {
		x.t.Fatal(err)
	}
}

func (x *k037) frozen(kind string) *informer.Informer {
	x.t.Helper()
	ictx, stop := context.WithCancel(x.ctx)
	inf := informer.New(x.c, kind)
	go inf.Run(ictx)
	if !inf.WaitSynced(x.ctx) {
		x.t.Fatalf("%s never synced", kind)
	}
	stop()
	return inf
}

func (x *k037) volumes() *provider.Volumes {
	return &provider.Volumes{Client: x.c, Silos: x.frozen("Silo"), Hosts: x.frozen("Host"), Plugins: x.reg, Records: x.st, Providers: x.known}
}

func (x *k037) reconcile(name string) {
	x.t.Helper()
	if _, err := x.volumes().Reconcile(x.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: name}); err != nil {
		x.t.Fatal(err)
	}
}

func (x *k037) get(name string) *v1.Silo {
	x.t.Helper()
	var s v1.Silo
	x.must(x.c.Get(x.ctx, "Silo", "d", name, &s))
	return &s
}

func (x *k037) silo(name, host string) *v1.Silo {
	s := &v1.Silo{TypeMeta: tm037("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Volumes: []v1.Volume{{Name: "data", Class: kplugintest.ClassBlock, Size: "1Gi", MountPath: "/data"}}}}
	x.must(x.c.Create(x.ctx, s))
	s.Status.Host, s.Status.Phase = host, "Scheduled"
	x.must(x.c.UpdateStatus(x.ctx, s))
	x.reconcile(name) // its finalizer
	x.reconcile(name) // created and attached
	return x.get(name)
}

// callsOn are the plugin calls since mark that name handle.
func (x *k037) callsOn(mark int, handle string) []string {
	var out []string
	for _, c := range x.fake.CallLog()[mark:] {
		if strings.Contains(c, " "+handle) {
			out = append(out, c)
		}
	}
	return out
}

// K-037: a volume's handle, class, region and device in a silo's status are inputs to the
// control plane's attach, detach and delete, and to the agent's format and mount. Whoever wrote
// them there (a worker, anyone with update on silos/status), the volumes controller acts only on
// what it recorded itself: a status that disagrees is put back, and no plugin call names the
// rewritten handle.
func TestK037TheVolumesControllerActsOnlyOnWhatItRecorded(t *testing.T) {
	x := newK037(t)
	other := x.silo("other", "w2") // its volume is the victim
	victim := other.Status.Volumes[0]
	s := x.silo("db", "w1")
	mine := s.Status.Volumes[0]
	if mine.Handle == "" || mine.Device == "" || mine.AttachedTo != "w1" {
		t.Fatalf("not attached: %+v", mine)
	}

	// Rewritten: the victim's handle, a device of the host's own.
	s.Status.Volumes[0].Handle, s.Status.Volumes[0].Device, s.Status.Volumes[0].Region = victim.Handle, "/dev/sda1", "elsewhere"
	x.must(x.c.UpdateStatus(x.ctx, s))
	mark := len(x.fake.CallLog())
	x.reconcile("db")
	if calls := x.callsOn(mark, victim.Handle); len(calls) > 0 {
		t.Fatalf("plugin calls on the rewritten handle %s: %v", victim.Handle, calls)
	}
	got := x.get("db").Status.Volumes[0]
	if got.Handle != mine.Handle || got.Device != mine.Device || got.Region != mine.Region {
		t.Fatalf("status not put back: %+v, want %+v", got, mine)
	}

	// Rewritten again, then the silo is deleted: the volume deleted is its own.
	s = x.get("db")
	s.Status.Volumes[0].Handle = victim.Handle
	x.must(x.c.UpdateStatus(x.ctx, s))
	x.must(x.c.Delete(x.ctx, "Silo", "d", "db"))
	mark = len(x.fake.CallLog())
	for range 4 {
		if _, err := x.volumes().Reconcile(x.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: "db"}); err != nil {
			t.Fatal(err)
		}
	}
	if calls := x.callsOn(mark, victim.Handle); len(calls) > 0 {
		t.Fatalf("plugin calls on the rewritten handle %s while deleting: %v", victim.Handle, calls)
	}
	_, vols, _ := x.fake.Snapshot()
	if _, ok := vols[victim.Handle]; !ok {
		t.Fatalf("the other silo's volume %s was deleted", victim.Handle)
	}
	if _, ok := vols[mine.Handle]; ok {
		t.Fatalf("its own volume %s is still there", mine.Handle)
	}
	// Its records go with it.
	recs, _, err := x.st.List(x.ctx, store.Selector{Kind: provider.VolumeRecordKind})
	x.must(err)
	for _, r := range recs {
		if strings.HasPrefix(r.Name, s.UID) {
			t.Fatalf("record %s left behind", r.Key)
		}
	}
}

// A volume status with a handle the control plane never recorded (written by someone else) is
// not acted on: the handle the plugin gives for the silo's own volume ID is used, and a removal
// of an unrecorded handle is refused, saying so.
func TestK037AnUnrecordedHandleIsNotTrusted(t *testing.T) {
	x := newK037(t)
	other := x.silo("other", "w2")
	victim := other.Status.Volumes[0]
	s := &v1.Silo{TypeMeta: tm037("Silo"), ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "d"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Volumes: []v1.Volume{{Name: "data", Class: kplugintest.ClassBlock, Size: "1Gi", MountPath: "/data"}}}}
	x.must(x.c.Create(x.ctx, s))
	s.Status.Host, s.Status.Phase = "w1", "Scheduled"
	s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: kplugintest.ClassBlock, Handle: victim.Handle, Region: "r", AttachedTo: "w1", Device: "/dev/sda1"}}
	x.must(x.c.UpdateStatus(x.ctx, s))
	mark := len(x.fake.CallLog())
	x.reconcile("db")
	x.reconcile("db")
	if calls := x.callsOn(mark, victim.Handle); len(calls) > 0 {
		t.Fatalf("plugin calls on an unrecorded handle %s: %v", victim.Handle, calls)
	}
	got := x.get("db").Status.Volumes[0]
	if got.Handle == victim.Handle || got.Device == "/dev/sda1" || got.Handle == "" {
		t.Fatalf("an unrecorded handle or device kept: %+v", got)
	}

	// A volume being removed whose handle was never recorded: not deleted on its say-so.
	s = x.get("db")
	s.Status.Volumes = append(s.Status.Volumes, v1.VolumeStatus{Name: "old", Class: kplugintest.ClassBlock, Handle: victim.Handle, AttachedTo: "w2"})
	x.must(x.c.UpdateStatus(x.ctx, s))
	mark = len(x.fake.CallLog())
	x.reconcile("db")
	if calls := x.callsOn(mark, victim.Handle); len(calls) > 0 {
		t.Fatalf("plugin calls removing an unrecorded handle %s: %v", victim.Handle, calls)
	}
	for _, v := range x.get("db").Status.Volumes {
		if v.Name == "old" && !strings.Contains(v.Message, "record") {
			t.Fatalf("the refusal isn't said: %+v", v)
		}
	}
}

// Host.status.provider names the machine the control plane attaches volumes to and sends
// balancer traffic to. A worker may write its own Host's status; what the control plane acts on
// is what the plugin said when the provider-hosts controller asked it, and a rewritten one is put
// back.
func TestK037AHostsProviderIsWhatThePluginSaid(t *testing.T) {
	x := newK037(t)
	var h v1.Host
	x.must(x.c.Get(x.ctx, "Host", "", "w1", &h))
	h.Status.Provider = &v1.HostProvider{Name: "fake", ID: "2", Region: "r", PrivateAddress: "192.168.0.2"} // w2's machine
	x.must(x.c.UpdateStatus(x.ctx, &h))
	s := x.silo("db", "w1")
	_, vols, _ := x.fake.Snapshot()
	if v := vols[s.Status.Volumes[0].Handle]; v.AttachedTo != "1" {
		t.Fatalf("w1's volume attached to machine %q, not w1's (1)", v.AttachedTo)
	}
	hosts := &provider.Hosts{Client: x.c, Hosts: x.frozen("Host"), Plugins: x.reg, Providers: x.known}
	if _, err := hosts.Reconcile(x.ctx, engine.Key{Kind: "Host", Name: "w1"}); err != nil {
		t.Fatal(err)
	}
	x.must(x.c.Get(x.ctx, "Host", "", "w1", &h))
	if h.Status.Provider == nil || h.Status.Provider.ID != "1" {
		t.Fatalf("w1's rewritten provider not put back: %+v", h.Status.Provider)
	}
}
