package agent_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// A mount-reach volume: the node side on this host mounts it once the control plane says it's
// this host's, the container gets that path, and the silo leaving unmounts it. Without a node
// side for the class, the silo waits, saying so.
func TestNodeSideMountsAVolume(t *testing.T) {
	for _, withNode := range []bool{true, false} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
		ts := httptest.NewServer(srv)
		c := client.New(ts.URL)
		_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
		share := kplugintest.New()
		rt := fake.New()
		a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}}
		if withNode {
			a.Nodes = &plugins.Registry{}
			if err := a.Nodes.Add(ctx, share.Node("hv1")); err != nil {
				t.Fatal(err)
			}
		}
		go a.Run(ctx)

		vs, _ := share.EnsureVolume(ctx, kplugintestVolume())
		s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "pad", Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "busybox"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Volumes: []v1.Volume{{Name: "home", Class: kplugintest.ClassShare, Size: "5Gi", MountPath: "/home"}}}}
		if err := c.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		// What the volumes controller writes: created, this host's to mount.
		s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
		s.Status.Volumes = []v1.VolumeStatus{{Name: "home", Class: kplugintest.ClassShare, Handle: vs.Handle, AttachedTo: "hv1"}}
		if err := c.UpdateStatus(ctx, s); err != nil {
			t.Fatal(err)
		}
		path := agent.DefaultVolumesDir + "/" + s.UID + "/home"
		wait := func(what string, ok func(*v1.Silo) bool) {
			t.Helper()
			for ctx.Err() == nil {
				var x v1.Silo
				if err := c.Get(ctx, "Silo", "dev", "pad", &x); err == nil && ok(&x) {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatalf("%s (node side %v): never; mounts %v", what, withNode, share.MountsOf(vs.Handle))
		}
		if !withNode {
			wait("waits for a node side", func(x *v1.Silo) bool {
				c := meta.FindCondition(x.Status.Conditions, "Ready")
				return c != nil && c.Reason == "VolumesPending" && strings.Contains(c.Message, "no plugin on hv1 mounts storage class fake-share")
			})
			cancel()
			ts.Close()
			continue
		}
		wait("mounted and running", func(x *v1.Silo) bool {
			spec, _ := rt.Spec(kri.ID{Namespace: "dev", Name: "pad", UID: s.UID})
			return meta.IsTrue(x.Status.Conditions, "Ready") && x.Status.Volumes[0].Mounted &&
				len(spec.Volumes) == 1 && spec.Volumes[0].HostPath == path
		})
		if m := share.MountsOf(vs.Handle); len(m) != 1 || m[0] != "hv1:"+path {
			t.Fatalf("mounts %v", m)
		}
		// Placed elsewhere: removed here and unmounted, saying so.
		var x v1.Silo
		_ = c.Get(ctx, "Silo", "dev", "pad", &x)
		x.Status.Host = "hv2"
		if err := c.UpdateStatus(ctx, &x); err != nil {
			t.Fatal(err)
		}
		wait("unmounted", func(x *v1.Silo) bool { return !x.Status.Volumes[0].Mounted && len(share.MountsOf(vs.Handle)) == 0 })
		cancel()
		ts.Close()
	}
}

func kplugintestVolume() kplugin.Volume {
	return kplugin.Volume{Class: kplugintest.ClassShare, ID: "u/home"}
}

// A mount-reach volume that stops answering (a JuiceFS mount whose metadata database is down:
// calls into it wait), or answers with errors (its client gave up after its retries, ~40s on
// Linodes), is said on the silo, VolumesResponding=False, while the silo stays Running; and back
// to True once it answers again.
func TestVolumeNotAnsweringIsSaid(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	defer cancel() // before the server closes: the agent's watches end first
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	share := kplugintest.New()
	var mu sync.Mutex
	mode := "ok"                // ok | hang | fail
	back := make(chan struct{}) // closed: hanging calls return
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": fake.New()}, Clock: clock.Real{},
		Nodes: &plugins.Registry{}, ProbeTimeout: 300 * time.Millisecond, ProbeEvery: 100 * time.Millisecond, Probe: func(string) error {
			mu.Lock()
			m := mode
			mu.Unlock()
			switch m {
			case "hang":
				<-back
				return errors.New("lstat: input/output error")
			case "fail":
				return errors.New("lstat /var/lib/kevaso/volumes/u/home/.kevaso-probe: input/output error")
			case "slowfail": // what a JuiceFS client does once it gives up: each call waits its retries out, then fails
				time.Sleep(500 * time.Millisecond)
				return errors.New("lstat: input/output error")
			}
			return nil
		}}
	set := func(m string) {
		mu.Lock()
		mode = m
		mu.Unlock()
	}
	if err := a.Nodes.Add(ctx, share.Node("hv1")); err != nil {
		t.Fatal(err)
	}
	go a.Run(ctx)
	vs, _ := share.EnsureVolume(ctx, kplugintestVolume())
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "pad", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "busybox"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Volumes: []v1.Volume{{Name: "home", Class: kplugintest.ClassShare, Size: "1Gi", MountPath: "/home"}}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	s.Status.Volumes = []v1.VolumeStatus{{Name: "home", Class: kplugintest.ClassShare, Handle: vs.Handle, AttachedTo: "hv1"}}
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	wait := func(what string, ok func(*v1.Silo, *meta.Condition) bool) {
		t.Helper()
		var x v1.Silo
		for ctx.Err() == nil {
			if err := c.Get(ctx, "Silo", "dev", "pad", &x); err == nil && ok(&x, meta.FindCondition(x.Status.Conditions, "VolumesResponding")) {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("%s: never; status %+v", what, x.Status)
	}
	wait("running, its volume answering", func(x *v1.Silo, c *meta.Condition) bool {
		return x.Status.Phase == agent.PhaseRunning && c != nil && c.Status == meta.ConditionTrue
	})
	set("hang")
	wait("said not answering, still Running", func(x *v1.Silo, c *meta.Condition) bool {
		return c != nil && c.Status == meta.ConditionFalse && c.Reason == "NotAnswering" &&
			strings.Contains(c.Message, "home ("+kplugintest.ClassShare+") hasn't answered") && x.Status.Phase == agent.PhaseRunning
	})
	set("fail")
	close(back) // the hung call returns an error, and so does every later one
	wait("said failing, still Running", func(x *v1.Silo, c *meta.Condition) bool {
		return c != nil && c.Status == meta.ConditionFalse && c.Reason == "Failing" &&
			strings.Contains(c.Message, "input/output error") && x.Status.Phase == agent.PhaseRunning
	})
	// Each call hanging, then failing: never "answering" in between (on Linodes the condition went
	// back to True while the next probe was still under its timeout).
	// Other changes to the silo make the agent look at it at any time, also just after a probe began.
	set("slowfail")
	for i, end := 0, time.Now().Add(3*time.Second); time.Now().Before(end); i++ {
		var x v1.Silo
		if err := c.Get(ctx, "Silo", "dev", "pad", &x); err == nil {
			if c := meta.FindCondition(x.Status.Conditions, "VolumesResponding"); c == nil || c.Status != meta.ConditionFalse {
				t.Fatalf("a volume whose calls hang then fail was said answering: %+v", c)
			}
			x.Labels = map[string]string{"poke": strconv.Itoa(i)}
			_ = c.Update(ctx, &x)
		}
		time.Sleep(15 * time.Millisecond)
	}
	set("ok")
	wait("answering again", func(x *v1.Silo, c *meta.Condition) bool { return c != nil && c.Status == meta.ConditionTrue })
}
