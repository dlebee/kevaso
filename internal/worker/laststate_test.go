package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// K-062: a kevasod that starts while the control plane is away comes up from what it kept: the
// worker's network loads its rules (and starts its DNS listeners and egress gate) from the last
// state it saw, instead of waiting for a control plane that isn't there.
func TestTheNetworkStartsFromTheLastStateWhenTheControlPlaneIsAway(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	api := httptest.NewServer(srv)
	defer api.Close()
	admin := client.New(api.URL)
	for _, o := range []meta.Object{
		&v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}},
		&v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
			Spec: v1.HostSpec{InternalIP: "10.0.0.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}},
	} {
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "nginx"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Ports: []v1.SiloPort{{Name: "web", Port: 8080}}, Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "web", HostPort: []string{v1.NetworkInternal}}}}}}
	if err := admin.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase, s.Status.SiloIP = "hv1", "Running", "10.64.0.2"
	if err := admin.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	applied := make(chan string, 64)
	old := applyRules
	applyRules = func(_ context.Context, rules string) error { applied <- rules; return nil }
	defer func() { applyRules = old }()
	file := filepath.Join(t.TempDir(), "last-state.json")
	run := func(c *client.Client) (stop func()) {
		rctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { RunNetworkWith(rctx, c, "hv1", nil, nil, t.Logf, NetworkOptions{StateFile: file}); close(done) }()
		return func() { cancel(); <-done }
	}
	waitRules := func(what string, within time.Duration) {
		t.Helper()
		deadline := time.After(within)
		for {
			select {
			case r := <-applied:
				if strings.Contains(r, "dnat ip to 10.64.0.2:8080") {
					return
				}
			case <-deadline:
				t.Fatalf("%s: the silo's port was never loaded", what)
			}
		}
	}
	stop := run(client.New(api.URL))
	waitRules("with the control plane", 10*time.Second)
	time.Sleep(300 * time.Millisecond) // saved after the pass
	stop()
	api.CloseClientConnections()

	away := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "away", http.StatusServiceUnavailable)
	}))
	defer away.Close()
	for len(applied) > 0 {
		<-applied
	}
	stop = run(client.New(away.URL))
	defer stop()
	waitRules("restarted with the control plane away", 5*time.Second)
}

// K-062: what a worker needs to start without its control plane, kept on disk: the last state
// and, on the mesh, its silo subnet. A first start (nothing kept) waits for the control plane.
func TestAWorkerStartsWithoutItsControlPlaneOnlyFromWhatItKept(t *testing.T) {
	dir := t.TempDir()
	if _, ok := keptStart(dir, true); ok {
		t.Fatal("nothing kept, and it would start without the control plane")
	}
	if err := keepSubnet(dir, netip.MustParsePrefix("10.64.3.0/24")); err != nil {
		t.Fatal(err)
	}
	if _, ok := keptStart(dir, true); ok {
		t.Fatal("a subnet but no last state: it would start with no rules to load")
	}
	if err := os.WriteFile(filepath.Join(dir, LastStateFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, ok := keptStart(dir, true); !ok || p.String() != "10.64.3.0/24" {
		t.Fatalf("kept: %v %v", p, ok)
	}
	if _, ok := keptStart(t.TempDir(), false); ok {
		t.Fatal("off the mesh with nothing kept")
	}
}
