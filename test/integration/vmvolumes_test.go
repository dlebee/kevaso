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

// A cloud-hypervisor silo with a mount-class volume and its own disk on the same class (ADR 0006):
// the node side mounts both on the silo's host, the VM gets the volume as a share (a host folder)
// and its disk's folder, its guest mounts the shares; a new volume restarts it; it's movable
// Anywhere, and a move lets go on the old host (VM stopped, both unmounted) before the new host
// mounts them and boots the same disk.
func TestVMVolumesFollowTheSilo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvv")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	share := kplugintest.New()
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
	hosts := []string{"hv1", "hv2"}
	runtimes := map[string]*fake.VM{}
	heartbeat := func(h *v1.Host) {
		now := time.Now().UTC().Truncate(time.Second)
		meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}, now)
		h.Status.LastHeartbeat = &now
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"cloud-hypervisor": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
		h.Status.MountClasses = []string{kplugintest.ClassShare}
	}
	for _, name := range hosts {
		h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{Address: "198.51.100.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "cloud-hypervisor"}}}}}}
		if err := admin.Create(ctx, h); err != nil {
			t.Fatal(err)
		}
		heartbeat(h)
		if err := admin.UpdateStatus(ctx, h); err != nil {
			t.Fatal(err)
		}
		rt := fake.NewVM()
		runtimes[name] = rt
		a := &agent.Agent{Client: admin, HostName: name, Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{},
			Nodes: &plugins.Registry{}}
		if err := a.Nodes.Add(ctx, share.Node(name)); err != nil {
			t.Fatal(err)
		}
		go a.Run(ctx)
	}
	go func() {
		for ctx.Err() == nil {
			for _, name := range hosts {
				var h v1.Host
				if admin.Get(ctx, "Host", "", name, &h) == nil {
					heartbeat(&h)
					_ = admin.UpdateStatus(ctx, &h)
				}
			}
			time.Sleep(time.Second)
		}
	}()

	if err := admin.Create(ctx, ns("notes")); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "vm", Namespace: "notes"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Image: "ubuntu-24.04", Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Disk:         v1.Disk{Class: kplugintest.ClassShare, Size: "20Gi"},
			Availability: v1.Availability{OnHostLoss: v1.OnHostLossMove}, // admitted: disk and volume go anywhere
			Volumes:      []v1.Volume{{Name: "home", Class: kplugintest.ClassShare, Size: "5Gi", MountPath: "/home"}}}}
	if err := admin.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	var cur v1.Silo
	get := func() *v1.Silo {
		if err := admin.Get(ctx, "Silo", "notes", "vm", &cur); err != nil {
			t.Fatal(err)
		}
		return &cur
	}
	volPath := func(x *v1.Silo, name string) string { return agent.DefaultVolumesDir + "/" + x.UID + "/" + name }
	// on: running on host, every volume (and the disk's) mounted there by the node side, the VM
	// given the shares and the disk's folder, its guest mounting the shares.
	on := func(x *v1.Silo, host string, names ...string) (bool, string) {
		id := kri.ID{Namespace: "notes", Name: "vm", UID: x.UID}
		spec, _ := runtimes[host].Spec(id)
		guest := runtimes[host].GuestMounts(id)
		ok := x.Status.Host == host && meta.IsTrue(x.Status.Conditions, "Ready") && spec.DiskHostPath == volPath(x, v1.RootDiskVolume) &&
			len(x.Status.Volumes) == len(names)+1 && len(spec.Volumes) == len(names) && len(guest) == len(names)
		for _, vs := range x.Status.Volumes {
			ok = ok && vs.AttachedTo == host && vs.Mounted && slices.Equal(share.MountsOf(vs.Handle), []string{host + ":" + volPath(x, vs.Name)})
		}
		for _, n := range names {
			i := slices.IndexFunc(spec.Volumes, func(v kri.Volume) bool { return v.Name == n })
			ok = ok && i >= 0 && spec.Volumes[i].HostPath == volPath(x, n)
		}
		return ok, x.Status.Host + " " + condMsgs(x.Status.Conditions) + " " + volMsgs(x.Status.Volumes) + " guest " + kvols(guest)
	}
	var first string
	eventually("vm running with its disk and volume on the mount class", func() (bool, string) {
		x := get()
		first = x.Status.Host
		if first == "" {
			return false, condMsgs(x.Status.Conditions)
		}
		return on(x, first, "home")
	})
	if get().Status.Movable != "Anywhere" {
		t.Fatalf("movable: %q", cur.Status.Movable)
	}
	for _, vs := range get().Status.Volumes {
		if vs.SizeBytes == 0 || !vs.SizeNotEnforced { // the fake share, like a folder without a quota
			t.Fatalf("volume %s: size %d, not enforced %v", vs.Name, vs.SizeBytes, vs.SizeNotEnforced)
		}
	}

	// A new volume: the VM restarts with it (no hot-add).
	x := get()
	x.Spec.Volumes = append(x.Spec.Volumes, v1.Volume{Name: "logs", Class: kplugintest.ClassShare, Size: "1Gi", MountPath: "/var/log/app"})
	if err := admin.Update(ctx, x); err != nil {
		t.Fatal(err)
	}
	eventually("vm restarted with its new volume", func() (bool, string) { return on(get(), first, "home", "logs") })
	id := kri.ID{Namespace: "notes", Name: "vm", UID: cur.UID}
	if calls := strings.Join(runtimes[first].CallLog(), "\n"); !strings.Contains(calls, "stop "+id.String()+"\nset-volumes "+id.String()) {
		t.Fatalf("not stopped before its volumes changed:\n%s", calls)
	}
	handles := map[string]string{}
	for _, vs := range get().Status.Volumes {
		handles[vs.Name] = vs.Handle
	}

	second := map[string]string{"hv1": "hv2", "hv2": "hv1"}[first]
	var out v1.Silo
	if err := admin.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/notes/silos/vm/move", moves.Request{To: second}, &out); err != nil {
		t.Fatal(err)
	}
	eventually("vm moved with its disk and volumes", func() (bool, string) { return on(get(), second, "home", "logs") })
	for _, vs := range get().Status.Volumes {
		if handles[vs.Name] != vs.Handle {
			t.Fatalf("volume %s is a new one on the new host: %s, was %s", vs.Name, vs.Handle, handles[vs.Name])
		}
	}
	if ids, _ := runtimes[first].List(ctx); len(ids) != 0 {
		t.Fatalf("still on %s: %v", first, ids)
	}
	// The old host stopped the VM and unmounted everything before the new one mounted anything.
	log := share.CallLog()
	lastUnmount, firstMount := -1, -1
	for i, c := range log {
		if strings.HasPrefix(c, "unmount "+first+" ") {
			lastUnmount = i
		}
		if strings.HasPrefix(c, "mount "+second+" ") && firstMount < 0 {
			firstMount = i
		}
	}
	if lastUnmount < 0 || firstMount < lastUnmount {
		t.Fatalf("unmount on %s, then mount on %s: %v", first, second, log)
	}
	if calls := runtimes[first].CallLog(); slices.Index(calls, "stop "+id.String()) < 0 {
		t.Fatalf("the old host never stopped it: %v", calls)
	}

	if err := admin.Delete(ctx, "Silo", "notes", "vm"); err != nil {
		t.Fatal(err)
	}
	eventually("deleting it unmounts and deletes the disk's and the volumes", func() (bool, string) {
		_, vols, _ := share.Snapshot()
		var y v1.Silo
		err := admin.Get(ctx, "Silo", "notes", "vm", &y)
		return len(vols) == 0 && client.IsNotFound(err), volMsgs(y.Status.Volumes)
	})
}

func kvols(vs []kri.Volume) string {
	var b []string
	for _, v := range vs {
		b = append(b, v.Name+"@"+v.HostPath)
	}
	return strings.Join(b, ",")
}
