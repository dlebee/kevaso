package agent_test

import (
	"context"
	"net/http/httptest"
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
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// puller is the fake runtime that pulls: each pull gets the digest the registry has now for the
// image, or fails with refuse's reason.
type puller struct {
	*fake.Runtime
	mu      sync.Mutex
	digests map[string]string
	refuse  string
	pulls   []string
}

func (p *puller) Pull(_ context.Context, _ kri.ID, image string, auth *kri.RegistryAuth) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pulls = append(p.pulls, image)
	if auth != nil {
		return "", &kri.PullError{Image: image, Reason: "unexpected credential"}
	}
	if p.refuse != "" {
		return "", &kri.PullError{Image: image, Reason: p.refuse}
	}
	return p.digests[image], nil
}

func (p *puller) set(image, digest, refuse string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.digests[image], p.refuse = digest, refuse
}

// The agent records the digest each pull got, before Create and before each reset, so an update
// shows even when the tag stayed the same; a pull that fails during an update leaves the old copy
// running (still Ready), with Updated saying ImagePullFailed and the registry's reason.
func TestDigestRecordedAndPullFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	d1, d2 := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	const img = "ghcr.io/acme/api:v1"
	rt := &puller{Runtime: fake.New(), digests: map[string]string{img: d1}}
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}}
	go a.Run(ctx)
	e := &env{c: c, ctx: ctx}

	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Image: img, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	e.wait(t, "api", func(s *v1.Silo) bool {
		return meta.IsTrue(s.Status.Conditions, "Ready") && s.Status.Image != nil && s.Status.Image.Digest == d1
	})

	// The tag moved: a reset pulls it again, and the new digest is what runs.
	rt.set(img, d2, "")
	reset := func(v string) {
		t.Helper()
		for {
			var cur v1.Silo
			_ = c.Get(ctx, "Silo", "dev", "api", &cur)
			cur.Spec.Reset = v
			if err := c.Update(ctx, &cur); !client.IsConflict(err) {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
		}
	}
	reset("r1")
	e.wait(t, "api", func(s *v1.Silo) bool {
		return s.Status.Image != nil && s.Status.Image.Reset == "r1" && s.Status.Image.Digest == d2 && meta.IsTrue(s.Status.Conditions, "Ready")
	})

	// The registry refuses: the old copy keeps running.
	rt.set(img, d2, "unauthorized: authentication required")
	reset("r2")
	got := e.wait(t, "api", func(s *v1.Silo) bool {
		cd := meta.FindCondition(s.Status.Conditions, "Updated")
		return cd != nil && cd.Reason == agent.ReasonImagePullFailed && strings.Contains(cd.Message, "unauthorized: authentication required")
	})
	if !meta.IsTrue(got.Status.Conditions, "Ready") || got.Status.Image.Reset != "r1" || got.Status.Image.Digest != d2 {
		t.Fatalf("a failed pull took the silo down or changed what it runs: %+v", got.Status)
	}
	if st, _ := rt.Status(ctx, kri.ID{Namespace: "dev", Name: "api", UID: got.UID}); st.State != kri.Running {
		t.Fatalf("stopped for a pull that failed: %v", st.State)
	}
}
