package integration

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controlplane"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin/kplugintest"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// A mount-reach storage class (M14: juicefs) in a real control plane with two real agents: the
// class is global, so the container silo is movable Anywhere and only goes to hosts running the
// plugin's node side; nothing is attached, the node side on the silo's host mounts the volume; a
// move unmounts it on the old host before the new host's node side mounts the same volume; and
// deleting the silo unmounts and deletes it.
func TestMountClassFollowsTheSilo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvm")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	share := kplugintest.New() // the plugin: its controller side on the control plane…
	reg := &plugins.Registry{Dir: filepath.Join(dir, "plugins")}
	if err := reg.Add(ctx, share); err != nil {
		t.Fatal(err)
	}
	if _, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", Address: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 100 * time.Millisecond,
		Plugins: reg}); err != nil {
		t.Fatal(err)
	}
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
	eventually := func(what string, cond func() (bool, string)) {
		t.Helper()
		last := ""
		for ctx.Err() == nil {
			ok, s := cond()
			if ok {
				return
			}
			last = s
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s: never happened; last: %s", what, last)
	}

	// hv1 and hv2 run the node side (…and its node side on each); hv3 doesn't.
	runtimes := map[string]*fake.Runtime{}
	heartbeat := func(name string, h *v1.Host) {
		now := time.Now().UTC().Truncate(time.Second)
		meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}, now)
		h.Status.LastHeartbeat = &now
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
		h.Status.MountClasses = nil
		if name != "hv3" {
			h.Status.MountClasses = []string{kplugintest.ClassShare} // what the worker reports from its node sides
		}
	}
	for _, name := range []string{"hv1", "hv2", "hv3"} {
		h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{Address: "198.51.100.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		if err := admin.Create(ctx, h); err != nil {
			t.Fatal(err)
		}
		heartbeat(name, h)
		if err := admin.UpdateStatus(ctx, h); err != nil {
			t.Fatal(err)
		}
		rt := fake.New()
		runtimes[name] = rt
		a := &agent.Agent{Client: admin, HostName: name, Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}}
		if name != "hv3" {
			a.Nodes = &plugins.Registry{}
			if err := a.Nodes.Add(ctx, share.Node(name)); err != nil {
				t.Fatal(err)
			}
		}
		go a.Run(ctx)
	}
	go func() {
		for ctx.Err() == nil {
			for _, name := range []string{"hv1", "hv2", "hv3"} {
				var h v1.Host
				if admin.Get(ctx, "Host", "", name, &h) == nil {
					heartbeat(name, &h)
					_ = admin.UpdateStatus(ctx, &h)
				}
			}
			time.Sleep(time.Second)
		}
	}()

	if err := admin.Create(ctx, ns("notes")); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "pad", Namespace: "notes"},
		Spec: v1.SiloSpec{Runtime: "docker", Image: "busybox", Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Placement:    v1.Placement{HostSelector: map[string]string{}},
			Availability: v1.Availability{OnHostLoss: v1.OnHostLossMove}, // admitted: the class can go anywhere
			Volumes:      []v1.Volume{{Name: "home", Class: kplugintest.ClassShare, Size: "5Gi", MountPath: "/home"}}}}
	if err := admin.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	var cur v1.Silo
	get := func() *v1.Silo {
		if err := admin.Get(ctx, "Silo", "notes", "pad", &cur); err != nil {
			t.Fatal(err)
		}
		return &cur
	}
	mountedOn := func(x *v1.Silo, host string) (bool, string) {
		vs := x.Status.Volumes
		if len(vs) != 1 {
			return false, x.Status.Host + " " + condMsgs(x.Status.Conditions)
		}
		at := share.MountsOf(vs[0].Handle)
		path := agent.DefaultVolumesDir + "/" + x.UID + "/home"
		spec, _ := runtimes[host].Spec(kri.ID{Namespace: "notes", Name: "pad", UID: x.UID})
		ok := x.Status.Host == host && meta.IsTrue(x.Status.Conditions, "Ready") && vs[0].AttachedTo == host && vs[0].Mounted &&
			vs[0].Device == "" && vs[0].Region == "" && slices.Equal(at, []string{host + ":" + path}) &&
			len(spec.Volumes) == 1 && spec.Volumes[0].HostPath == path && spec.Volumes[0].MountPath == "/home"
		return ok, x.Status.Host + " " + strings.Join(at, ",") + " " + condMsgs(x.Status.Conditions) + " " + volMsgs(vs)
	}
	var first string
	eventually("pad running with its volume mounted by the node side", func() (bool, string) {
		x := get()
		if x.Status.Host == "" {
			return false, condMsgs(x.Status.Conditions)
		}
		first = x.Status.Host
		return mountedOn(x, first)
	})
	if first == "hv3" {
		t.Fatal("placed on a host without the node side")
	}
	handle := get().Status.Volumes[0].Handle
	if get().Status.Movable != "Anywhere" {
		t.Fatalf("movable: %q", cur.Status.Movable)
	}
	for _, c := range share.CallLog() {
		if strings.HasPrefix(c, "attach ") || strings.HasPrefix(c, "detach ") {
			t.Fatalf("a mount class was attached: %v", share.CallLog())
		}
	}

	mv := func(to string) error {
		var out v1.Silo
		return admin.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/notes/silos/pad/move", moves.Request{To: to}, &out)
	}
	if err := mv("hv3"); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "node side") {
		t.Fatalf("moving to a host without the node side: %v", err)
	}
	second := map[string]string{"hv1": "hv2", "hv2": "hv1"}[first]
	if err := mv(second); err != nil {
		t.Fatal(err)
	}
	eventually("pad moved with its volume", func() (bool, string) { return mountedOn(get(), second) })
	if get().Status.Volumes[0].Handle != handle {
		t.Fatalf("a new volume on the new host: %s, was %s", cur.Status.Volumes[0].Handle, handle)
	}
	if ids, _ := runtimes[first].List(ctx); len(ids) != 0 {
		t.Fatalf("still on %s: %v", first, ids)
	}
	// The old host let go before the new one mounted it.
	log := share.CallLog()
	unmounted, mounted := -1, -1
	for i, c := range log {
		if strings.HasPrefix(c, "unmount "+first+" ") && unmounted < 0 {
			unmounted = i
		}
		if strings.HasPrefix(c, "mount "+second+" ") && mounted < 0 {
			mounted = i
		}
	}
	if unmounted < 0 || mounted < unmounted {
		t.Fatalf("unmount on %s, then mount on %s: %v", first, second, log)
	}

	if err := admin.Delete(ctx, "Silo", "notes", "pad"); err != nil {
		t.Fatal(err)
	}
	eventually("deleting it unmounts and deletes the volume", func() (bool, string) {
		_, vols, _ := share.Snapshot()
		var x v1.Silo
		err := admin.Get(ctx, "Silo", "notes", "pad", &x)
		return len(vols) == 0 && len(share.MountsOf(handle)) == 0 && client.IsNotFound(err), volMsgs(x.Status.Volumes) + strings.Join(x.Finalizers, ",")
	})
}
