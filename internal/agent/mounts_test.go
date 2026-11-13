package agent_test

import (
	"context"
	"net/http/httptest"
	"strings"
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
			Spec: v1.SiloSpec{Runtime: "docker", Image: "busybox", Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
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
