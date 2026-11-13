package integration

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// File and env secrets on container silos (ADR 0009 addendum), through the API with the real
// agent and a fake container runtime: admission takes them (env with a warning the user sees, a
// file only in a folder under /run); the files are there before the init steps and the command,
// change in place when rotated; a rotated variable waits for the next start; the values leave the
// host when it stops; a silo placed on another host gets them there and leaves none behind.
func TestContainerFileAndEnvSecrets(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	for _, s := range []*v1.Secret{secretObj("tls-key", nil, "KEY-1"), secretObj("legacy-token", nil, "tok-1")} {
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.admin.Create(c.ctx, grantObj("app", v1.GrantSpec{Secrets: []v1.GrantSecret{
		{Name: "tls-key", Deliver: v1.DeliverFile, Path: "/run/secrets/tls.pem"},
		{Name: "legacy-token", Deliver: v1.DeliverEnv},
	}})); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, grantObj("flat", v1.GrantSpec{Secrets: []v1.GrantSecret{
		{Name: "tls-key", Deliver: v1.DeliverFile, Path: "/run/tls.pem"},
	}})); err != nil {
		t.Fatal(err)
	}

	// Admission: a file straight in /run is refused on a container (its folder is mounted
	// read-only), not on a VM; OpenShell still refuses file and env, saying why.
	flat := containerSilo("flat", "web3", "docker")
	flat.Spec.Grants = []string{"flat"}
	if err := c.admin.Create(c.ctx, flat); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "not in /run itself") {
		t.Fatalf("a file in /run on docker: %v", err)
	}
	vm := silo("flat-vm", "web3")
	vm.Spec.Grants = []string{"flat"}
	if err := c.admin.Create(c.ctx, vm); err != nil {
		t.Fatalf("a file in /run on a VM: %v", err)
	}
	os := containerSilo("sandbox", "web3", "openshell-container")
	os.Spec.Grants = []string{"app"}
	if err := c.admin.Create(c.ctx, os); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "without something of Kevaso's inside it") {
		t.Fatalf("file on openshell: %v", err)
	}

	// Two hosts with the fake container runtime.
	boxes := map[string]*fake.Box{"hv1": fake.NewBox(), "hv2": fake.NewBox()}
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	for h, b := range boxes {
		a := &agent.Agent{Client: c.host(t, h), HostName: h, Runtimes: map[string]kri.Runtime{"docker": b}, Clock: clock.Real{}}
		go a.Run(ctx)
	}

	// The silo: accepted, with a warning for its env secret that kvo prints.
	var mu sync.Mutex
	var warnings []string
	c.admin.Warnings = func(w string) { mu.Lock(); warnings = append(warnings, w); mu.Unlock() }
	defer func() { c.admin.Warnings = nil }()
	s := containerSilo("api", "web3", "docker")
	s.Spec.Grants = []string{"app"}
	s.Spec.Init = &v1.Init{Steps: []v1.InitStep{{Name: "check", Run: "test -f /run/secrets/tls.pem"}}}
	if err := c.admin.Create(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "secret legacy-token goes in as an environment variable") || !strings.Contains(warnings[0], "docker inspect") {
		t.Fatalf("warnings: %q", warnings)
	}
	mu.Unlock()
	c.admin.Warnings = nil
	s.Status.Host = "hv1"
	if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for !ok() {
			select {
			case <-ctx.Done():
				t.Fatalf("waiting for %s", what)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	cond := func(want string) func() bool {
		return func() bool {
			var cur v1.Silo
			_ = c.admin.Get(c.ctx, "Silo", "web3", "api", &cur)
			for _, cd := range cur.Status.Conditions {
				if cd.Type == "SecretsDelivered" && cd.Status == meta.ConditionTrue && strings.Contains(cd.Message, want) {
					return true
				}
			}
			return false
		}
	}
	b1 := boxes["hv1"]
	id := func() kri.ID {
		var cur v1.Silo
		_ = c.admin.Get(c.ctx, "Silo", "web3", "api", &cur)
		return kri.ID{Namespace: "web3", Name: "api", UID: cur.UID}
	}()
	waitFor("the secrets in the running silo", func() bool {
		f, _ := b1.File(id, "/run/secrets/tls.pem")
		e, _ := b1.Env(id, "LEGACY_TOKEN")
		st, _ := b1.Status(ctx, id)
		return f == "KEY-1" && e == "tok-1" && st.State == kri.Running
	})
	if saw := b1.InitSaw["api/check"]; saw["/run/secrets/tls.pem"] != "KEY-1" {
		t.Fatalf("the init step didn't find the file: %v", saw)
	}
	calls := strings.Join(b1.Calls, "\n")
	if i, j := strings.Index(calls, "set-secrets"), strings.Index(calls, "init check"); i < 0 || j < 0 || i > j || j > strings.Index(calls, "start web3/api") {
		t.Fatalf("secrets set after the init step or the start:\n%s", calls)
	}
	waitFor("SecretsDelivered", cond("1 files (a tmpfs of the host's, mounted read-only), 1 environment variables; "+agent.EnvInEngineNote))

	// The file rotated: in place, no restart.
	starts := strings.Count(strings.Join(b1.Calls, "\n"), "start web3/api")
	var tls v1.Secret
	_ = c.admin.Get(c.ctx, "Secret", "web3", "tls-key", &tls)
	tls.Spec.Value = []byte("KEY-2")
	if err := c.admin.Update(c.ctx, &tls); err != nil {
		t.Fatal(err)
	}
	waitFor("the file rotated", func() bool { f, _ := b1.File(id, "/run/secrets/tls.pem"); return f == "KEY-2" })
	// The variable rotated: the command keeps its value until the next start, and the condition
	// says so.
	var tok v1.Secret
	_ = c.admin.Get(c.ctx, "Secret", "web3", "legacy-token", &tok)
	tok.Spec.Value = []byte("tok-2")
	if err := c.admin.Update(c.ctx, &tok); err != nil {
		t.Fatal(err)
	}
	waitFor("the pending variable said", cond("environment variables take effect at the next start"))
	if e, _ := b1.Env(id, "LEGACY_TOKEN"); e != "tok-1" {
		t.Fatalf("the running command's variable changed to %q", e)
	}
	if n := strings.Count(strings.Join(b1.Calls, "\n"), "start web3/api"); n != starts {
		t.Fatalf("restarted for a rotation (%d starts, was %d)", n, starts)
	}

	// Placed on another host: its secrets there, nothing of them left on the first.
	var cur v1.Silo
	_ = c.admin.Get(c.ctx, "Silo", "web3", "api", &cur)
	cur.Status.Host = "hv2"
	if err := c.admin.UpdateStatus(c.ctx, &cur); err != nil {
		t.Fatal(err)
	}
	b2 := boxes["hv2"]
	waitFor("the secrets on hv2", func() bool {
		f, _ := b2.File(id, "/run/secrets/tls.pem")
		e, _ := b2.Env(id, "LEGACY_TOKEN")
		return f == "KEY-2" && e == "tok-2"
	})
	waitFor("nothing left on hv1", func() bool { return !b1.Known(id) && b1.HostValues(id) == 0 })
	if st, _ := b1.Status(ctx, id); st.State != kri.Absent {
		t.Fatalf("still on hv1: %s", st.State)
	}

	// The grant gives them another way (the local endpoint): off the host.
	var g v1.Grant
	_ = c.admin.Get(c.ctx, "Grant", "web3", "app", &g)
	g.Spec.Secrets = []v1.GrantSecret{{Name: "tls-key", Deliver: v1.DeliverBroker}}
	if err := c.admin.Update(c.ctx, &g); err != nil {
		t.Fatal(err)
	}
	waitFor("the values gone from hv2", func() bool { return b2.HostValues(id) == 0 })

	// Deleted: nothing left.
	if err := c.admin.Delete(c.ctx, "Silo", "web3", "api"); err != nil {
		t.Fatal(err)
	}
	waitFor("deleted on hv2", func() bool { return !b2.Known(id) })
}
