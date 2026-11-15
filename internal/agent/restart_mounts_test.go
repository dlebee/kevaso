package agent_test

import (
	"context"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/hostexec"
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

// mountTable is a host whose mount table is what the fake plugin's node side has mounted.
type mountTable struct {
	share  *kplugintest.Fake
	handle *string
}

func (m mountTable) Run(_ context.Context, c hostexec.Cmd) (int, error) {
	if c.Name == "mountpoint" && len(c.Args) > 0 {
		at := "hv1:" + c.Args[len(c.Args)-1]
		for _, h := range m.share.MountsOf(*m.handle) {
			if h == at {
				return 0, nil
			}
		}
		return 32, nil
	}
	return 0, nil
}
func (mountTable) WriteFile(string, []byte, os.FileMode) error { return nil }
func (mountTable) ReadFile(string) ([]byte, error)             { return nil, os.ErrNotExist }
func (mountTable) RemoveAll(string) error                      { return nil }
func (mountTable) Glob(string) ([]string, error)               { return nil, nil }

// A mount-reach volume's mount gone while kevasod runs (the node side, or its FUSE daemon,
// restarted or died): the agent trusted what it had mounted in this run and never mounted it
// again, so the silo's next start wrote into the plain folder on the host's root disk.
func TestALostNodeMountIsMountedAgain(t *testing.T) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel() // before the server closes: the agent's watches end first
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	share := kplugintest.New()
	var handle string
	rt := fake.New()
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{},
		Nodes: &plugins.Registry{}, Host: mountTable{share, &handle}}
	node := share.Node("hv1")
	if err := a.Nodes.Add(ctx, node); err != nil {
		t.Fatal(err)
	}
	vs, _ := share.EnsureVolume(ctx, kplugin.Volume{Class: kplugintest.ClassShare, ID: "u/home"})
	handle = vs.Handle
	agent.RunForTest(t, ctx, a)
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "pad", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "busybox"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Volumes: []v1.Volume{{Name: "home", Class: kplugintest.ClassShare, Size: "5Gi", MountPath: "/home"}}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	s.Status.Volumes = []v1.VolumeStatus{{Name: "home", Class: kplugintest.ClassShare, Handle: vs.Handle, AttachedTo: "hv1"}}
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	path := agent.DefaultVolumesDir + "/" + s.UID + "/home"
	mounted := func() bool { return slices.Contains(share.MountsOf(vs.Handle), "hv1:"+path) }
	for !mounted() {
		select {
		case <-ctx.Done():
			t.Fatal("never mounted")
		case <-time.After(10 * time.Millisecond):
		}
	}
	// The node side's mount goes away behind the agent's back.
	if err := node.UnmountVolume(ctx, kplugin.NodeMount{Handle: vs.Handle, Path: path}); err != nil {
		t.Fatal(err)
	}
	touch(t, ctx, c, "dev", "pad") // the agent looks again (as its 30s resync would)
	for !mounted() {
		select {
		case <-ctx.Done():
			t.Fatalf("never mounted again; calls %s", strings.Join(share.CallLog(), "; "))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// touch changes a silo's labels, so the agent reconciles it now.
func touch(t *testing.T, ctx context.Context, c *client.Client, ns, name string) {
	t.Helper()
	for range 50 { // the agent writes this silo's status too (probes, claims): read again on a conflict
		var s v1.Silo
		if err := c.Get(ctx, "Silo", ns, name, &s); err != nil {
			t.Fatal(err)
		}
		if s.Labels == nil {
			s.Labels = map[string]string{}
		}
		s.Labels["kevaso.test/touched"] = time.Now().Format("150405.000000")
		err := c.Update(ctx, &s)
		if !client.IsConflict(err) {
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("kept conflicting")
}
