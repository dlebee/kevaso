package integration

import (
	"strings"
	"sync"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Admission warns about an env secret on a container silo only where the engine would keep its
// value: when every host that can run the silo starts containers through Kevaso's OCI runtime
// (the worker reports RuntimeStatus.EnvOutsideEngine), there's nothing to warn about.
func TestEnvSecretWarningFollowsTheHosts(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	if err := c.admin.Create(c.ctx, secretObj("legacy-token", nil, "tok-1")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, grantObj("app", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "legacy-token", Deliver: v1.DeliverEnv}}})); err != nil {
		t.Fatal(err)
	}
	host := func(name string, outside bool) {
		t.Helper()
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{ExternalIP: "203.0.113.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		if err := c.admin.Create(c.ctx, h); err != nil {
			_ = c.admin.Get(c.ctx, "Host", "", name, h)
		}
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready", EnvOutsideEngine: outside}}
		if err := c.admin.UpdateStatus(c.ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	var warnings []string
	c.admin.Warnings = func(w string) { mu.Lock(); warnings = append(warnings, w); mu.Unlock() }
	defer func() { c.admin.Warnings = nil }()
	create := func(name string) []string {
		t.Helper()
		mu.Lock()
		warnings = nil
		mu.Unlock()
		s := containerSilo(name, "web3", "docker")
		s.Spec.Grants = []string{"app"}
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), warnings...)
	}
	host("hv1", true)
	host("hv2", true)
	if w := create("kept-out"); len(w) != 0 {
		t.Fatalf("warned with every host through the runtime: %q", w)
	}
	host("hv2", false) // podman, rootless, a non-runc default: --env-file there
	if w := create("may-be-in"); len(w) != 1 || !strings.Contains(w[0], "without Kevaso's OCI runtime") {
		t.Fatalf("warnings %q", w)
	}
}
