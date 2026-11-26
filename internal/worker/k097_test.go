package worker

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/gate"
	"kevaso.com/core/internal/names"
	"kevaso.com/core/internal/store"
)

// K-097: a held worker (its control plane is older than what it saw, §0.7) is still handed that
// control plane's answers, and its caches load them. What it serves (rules, DNS, the egress gate)
// must be the last state it trusted, from disk, not those older answers. Here the worker saved
// its last state with silo "web" (port 8080, grant "api") and is restarted held, against a
// control plane that says "web" and "api" are gone and an "old" silo (port 9090, grant "leak")
// runs instead: it loads web's rules and never old's, its DNS answers web and not old, and its
// gate knows "api" and not "leak", until the hold ends.
func TestAHeldWorkerServesTheLastTrustedStateFromDisk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	grant := func(name, to string) {
		t.Helper()
		if err := admin.Create(ctx, &v1.Grant{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Grant"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: to}}}}); err != nil {
			t.Fatal(err)
		}
	}
	place := func(name, ip string, port int, grant string) {
		t.Helper()
		s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "docker", Grants: []string{grant}, Container: &v1.ContainerSource{Image: "nginx"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Ports: []v1.SiloPort{{Name: "web", Port: port}}, Services: []v1.SiloService{{Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: v1.NetworkInternal}, Ports: []v1.ServicePort{{Port: "web"}}}}}}
		if err := admin.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host, s.Status.Phase, s.Status.SiloIP = "hv1", "Running", ip
		if err := admin.UpdateStatus(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	grant("api", "api.example.com")
	place("web", "10.64.0.2", 8080, "api")
	const webRule, oldRule = "dnat ip to 10.64.0.2:8080", "dnat ip to 10.64.0.3:9090"
	applied := make(chan string, 256)
	old := applyRules
	applyRules = func(_ context.Context, rules string) error { applied <- rules; return nil }
	defer func() { applyRules = old }()
	// The DNS listener for silos and the gate, as the network starts them (not listening).
	var dnsOn atomic.Pointer[DNS]
	var gateOn atomic.Pointer[egress]
	oldDNS, oldGate := runDNS, runGate
	runDNS = func(_ context.Context, d *DNS) {
		if d.From == names.FromSilo {
			dnsOn.Store(d)
		}
	}
	runGate = func(_ context.Context, e *egress) { gateOn.Store(e) }
	defer func() { runDNS, runGate = oldDNS, oldGate }()
	ca, err := gate.LoadOrCreateCA(t.TempDir(), "hv1")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), LastStateFile)
	var held atomic.Bool
	run := func() (stop func()) {
		rctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		dnsOn.Store(nil)
		gateOn.Store(nil)
		go func() {
			RunNetworkWith(rctx, client.New(api.URL), "hv1", ca, nil, t.Logf, NetworkOptions{StateFile: file, Held: held.Load})
			close(done)
		}()
		return func() { cancel(); <-done }
	}
	// waitRules waits for a ruleset with want (and without not); fails on one with not.
	waitRules := func(what, want, not string, within time.Duration) {
		t.Helper()
		deadline := time.After(within)
		for {
			select {
			case r := <-applied:
				if not != "" && strings.Contains(r, not) {
					t.Fatalf("%s: rules from the older control plane were loaded (%s)", what, not)
				}
				if strings.Contains(r, want) {
					return
				}
			case <-deadline:
				t.Fatalf("%s: no rules with %s", what, want)
			}
		}
	}
	stop := run()
	waitRules("trusted", webRule, "", 10*time.Second)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if b, err := os.ReadFile(file); err == nil && strings.Contains(string(b), `"10.64.0.2"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the last state was never saved")
		}
	}
	stop()

	// The control plane now answers an older state: web gone, old running.
	if err := admin.Delete(ctx, "Silo", "dev", "web"); err != nil {
		t.Fatal(err)
	}
	if err := admin.Delete(ctx, "Grant", "dev", "api"); err != nil {
		t.Fatal(err)
	}
	grant("leak", "leak.example.com")
	place("old", "10.64.0.3", 9090, "leak")
	for len(applied) > 0 {
		<-applied
	}
	held.Store(true)
	stop = run()
	defer func() { stop() }()
	waitRules("restarted held", webRule, oldRule, 10*time.Second)
	// Held for a while, answers keep coming: still the trusted rules only.
	end := time.After(2500 * time.Millisecond)
	for wait := true; wait; {
		select {
		case r := <-applied:
			if strings.Contains(r, oldRule) || !strings.Contains(r, webRule) {
				t.Fatalf("held: a ruleset other than the trusted one was loaded:\n%s", r)
			}
		case <-end:
			wait = false
		}
	}
	if b, _ := os.ReadFile(file); strings.Contains(string(b), `"10.64.0.3"`) {
		t.Fatal("held: the older control plane's state was saved as the last state")
	}
	served := func(what string, wantWeb bool) {
		t.Helper()
		d, e := dnsOn.Load(), gateOn.Load()
		if d == nil || e == nil {
			t.Fatalf("%s: the DNS listener or the gate wasn't started", what)
		}
		found := func(name string) bool {
			a := names.Resolve(names.Question{Name: name + ".dev.kevaso", From: names.FromSilo}, d.View())
			return len(a.IPs) > 0
		}
		if found("web") != wantWeb || found("old") == wantWeb {
			t.Errorf("%s: DNS answers web %v, old %v", what, found("web"), found("old"))
		}
		var gs []string
		for _, g := range e.grants() {
			gs = append(gs, g.Name)
		}
		var ss []string
		for _, s := range e.silos() {
			ss = append(ss, s.Name)
		}
		want, wantSilo := "api", "web"
		if !wantWeb {
			want, wantSilo = "leak", "old"
		}
		if strings.Join(gs, ",") != want || strings.Join(ss, ",") != wantSilo {
			t.Errorf("%s: the gate knows grants %v and silos %v, want %s and %s", what, gs, ss, want, wantSilo)
		}
	}
	served("held", true)
	// The hold ends: the control plane's state is served.
	held.Store(false)
	waitRules("the hold ended", oldRule, "", 10*time.Second)
	served("the hold ended", false)
}
