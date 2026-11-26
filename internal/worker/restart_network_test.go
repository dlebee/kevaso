package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
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

// After a kevasod restart, the first ruleset RunNetwork applies must already know the open
// leases (and services, ingresses): one built before the Lease informer synced closed every leased
// port and reset the connections a valid lease had let in.
func TestRunNetworkFirstApplyAfterARestartKeepsOpenLeases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	api := httptest.NewServer(srv)
	defer api.Close()
	admin := client.New(api.URL)
	mk := func(o meta.Object) {
		t.Helper()
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	mk(&v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	mk(&v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{ExternalIP: "198.51.100.10", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}})
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "nginx"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Ports:    []v1.SiloPort{{Name: "debug", Port: 9229}},
			Services: []v1.SiloService{{Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "debug", Sources: []string{"203.0.113.7"}, Lease: &v1.PortLease{Max: "1h"}}}}}}}
	mk(s)
	s.Status.Host, s.Status.Phase, s.Status.SiloIP = "hv1", "Running", "10.64.2.2"
	if err := admin.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	var ans client.LeaseAnswer
	if err := admin.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/api/open", v1.LeaseOpenRequest{Port: "debug", For: "30m"}, &ans); err != nil {
		t.Fatal(err)
	}

	// The restarted kevasod's Lease list is slow to come back (the others aren't).
	target, _ := url.Parse(api.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/leases") && r.URL.Query().Get("watch") == "" {
			time.Sleep(500 * time.Millisecond)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer slow.Close()

	applied := make(chan string, 16)
	old := applyRules
	applyRules = func(_ context.Context, rules string) error { applied <- rules; return nil }
	defer func() { applyRules = old }()
	done := make(chan struct{})
	go func() { RunNetwork(ctx, client.New(slow.URL), "hv1", nil, nil, func(string, ...any) {}); close(done) }()
	defer func() { cancel(); <-done; slow.CloseClientConnections(); api.CloseClientConnections() }()

	select {
	case rules := <-applied:
		if !strings.Contains(rules, "dport 9229 dnat") || strings.Contains(rules, "dport 9229 ct status dnat ct original ip daddr 198.51.100.10 reject") ||
			strings.Contains(rules, "reject with tcp reset") {
			t.Fatalf("the first ruleset after a restart closed an open lease:\n%s", rules)
		}
	case <-ctx.Done():
		t.Fatal("nothing applied")
	}
}
