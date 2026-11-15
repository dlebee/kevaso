package agent_test

import (
	"context"
	"net/http/httptest"
	"sync/atomic"
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

// badPuller can't pull anything.
type badPuller struct {
	*fake.Runtime
	pulls atomic.Int32
}

func (b *badPuller) Pull(_ context.Context, _ kri.ID, image string, _ *kri.RegistryAuth) (string, error) {
	b.pulls.Add(1)
	return "", &kri.PullError{Image: image, Reason: "pull access denied"}
}

// Found on the machine (TestMetalBadImages): an image that doesn't exist was pulled again
// thousands of times in minutes. Each failure's status write came back as a change, and the
// change started the next pull at once, whatever the backoff said.
func TestAFailedPullWaitsBeforeTheNext(t *testing.T) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	rt := &badPuller{Runtime: fake.New()}
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}}
	go a.Run(ctx)
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "missing", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "docker.io/library/nope:never"}, Resources: v1.Resources{CPU: 1, Memory: "64Mi"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	if n := rt.pulls.Load(); n == 0 || n > 3 {
		t.Fatalf("%d pulls in 3 seconds: want the first and then a backoff", n)
	}
	var cur v1.Silo
	_ = c.Get(ctx, "Silo", "dev", "missing", &cur)
	if cd := meta.FindCondition(cur.Status.Conditions, "Ready"); cd == nil || cd.Reason != agent.ReasonImagePullFailed {
		t.Fatalf("the reason isn't said: %+v", cur.Status.Conditions)
	}
}
