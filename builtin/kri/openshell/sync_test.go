package openshell_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/openshell"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
)

// bornPolicy is the policy file a sandbox was created with, for a silo whose grants open egress
// (nil: no grants). The agent is started only after the silo and its grants are stored.
func bornPolicy(t *testing.T, egress []v1.EgressRule) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	key, err := kms.OpenLocal(t.TempDir() + "/k.json")
	if err != nil {
		t.Fatal(err)
	}
	srv.SetVault(&secrets.Vault{Store: st, KMS: key, Now: time.Now})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	if len(egress) > 0 {
		g := &v1.Grant{TypeMeta: tm("Grant"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
			Spec: v1.GrantSpec{Egress: egress}}
		if err := c.Create(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "box", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "openshell", Container: &v1.ContainerSource{Image: "ubuntu-24.04"},
			Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if len(egress) > 0 {
		s.Spec.Grants = []string{"web"}
	}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	h := openshell.NewTestHost()
	var logMu sync.Mutex
	logEnded := false
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"openshell": h.Runtime()},
		Clock: clock.Real{}, ClaimRefresh: time.Hour,
		Log: func(f string, args ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			if !logEnded {
				t.Logf(f, args...)
			}
		}}
	runCtx, runCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(runCtx)
	}()
	t.Cleanup(func() {
		runCancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Errorf("the agent did not stop")
		}
		logMu.Lock()
		logEnded = true
		logMu.Unlock()
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		if got := h.Born(); got != "" {
			return got
		}
		if time.Now().After(deadline) {
			var cur v1.Silo
			_ = c.Get(context.Background(), "Silo", "dev", "box", &cur)
			t.Fatalf("sandbox was not created; status=%+v conditions=%v\n%s", cur.Status.Phase, cur.Status.Conditions, h.Commands())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// bornWhenTheGrantArrives is the policy at sandbox create when the grant is added while the
// runtime is not starting the silo, and only then is the silo allowed to start.
func bornWhenTheGrantArrives(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	key, err := kms.OpenLocal(t.TempDir() + "/k.json")
	if err != nil {
		t.Fatal(err)
	}
	srv.SetVault(&secrets.Vault{Store: st, KMS: key, Now: time.Now})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	g := &v1.Grant{TypeMeta: tm("Grant"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "api.gitlab.com"}}}}
	if err := c.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "box", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "openshell", Container: &v1.ContainerSource{Image: "ubuntu-24.04"},
			Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	var ready atomic.Bool
	h := openshell.NewTestHost()
	var logMu sync.Mutex
	logEnded := false
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"openshell": h.Runtime()},
		Clock: clock.Real{}, ClaimRefresh: time.Hour,
		RuntimeReady: func(string) bool { return ready.Load() },
		Log: func(f string, args ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			if !logEnded {
				t.Logf(f, args...)
			}
		}}
	runCtx, runCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(runCtx)
	}()
	t.Cleanup(func() {
		runCancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Errorf("the agent did not stop")
		}
		logMu.Lock()
		logEnded = true
		logMu.Unlock()
	})
	time.Sleep(300 * time.Millisecond) // it has seen the silo and is waiting, not creating it
	for attempt := 0; ; attempt++ {
		var cur v1.Silo
		if err := c.Get(ctx, "Silo", "dev", "box", &cur); err != nil {
			t.Fatal(err)
		}
		cur.Spec.Grants = []string{"web"}
		err := c.Update(ctx, &cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) || attempt > 20 {
			t.Fatal(err)
		}
	}
	ready.Store(true) // the grant is stored; the next start creates the sandbox with it
	deadline := time.Now().Add(15 * time.Second)
	for {
		if got := h.Born(); got != "" {
			return got
		}
		if time.Now().After(deadline) {
			var cur v1.Silo
			_ = c.Get(context.Background(), "Silo", "dev", "box", &cur)
			t.Fatalf("sandbox was not created after the grant; status=%+v conditions=%v\n%s", cur.Status.Phase, cur.Status.Conditions, h.Commands())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func policyApplied(s v1.Silo) (status, reason string, ok bool) {
	for _, c := range s.Status.Conditions {
		if c.Type == "PolicyApplied" {
			return string(c.Status), c.Reason, true
		}
	}
	return "", "", false
}

// A push that fails is not reported as applied. Once the push succeeds, the condition says so
// and the policy file is the grant that was pushed.
func TestAFailedPushIsNotReportedApplied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	key, err := kms.OpenLocal(t.TempDir() + "/k.json")
	if err != nil {
		t.Fatal(err)
	}
	srv.SetVault(&secrets.Vault{Store: st, KMS: key, Now: time.Now})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	g := &v1.Grant{TypeMeta: tm("Grant"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "api.github.com"}}}}
	if err := c.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "box", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "openshell", Container: &v1.ContainerSource{Image: "ubuntu-24.04"},
			Resources: v1.Resources{CPU: 1, Memory: "256Mi"}, Grants: []string{"web"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	h := openshell.NewTestHost()
	var logMu sync.Mutex
	logEnded := false
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"openshell": h.Runtime()},
		Clock: clock.Real{}, ClaimRefresh: time.Hour,
		Log: func(f string, args ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			if !logEnded {
				t.Logf(f, args...)
			}
		}}
	runCtx, runCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(runCtx)
	}()
	t.Cleanup(func() {
		runCancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Errorf("the agent did not stop")
		}
		logMu.Lock()
		logEnded = true
		logMu.Unlock()
	})
	wait := func(wantStatus, wantReason, host string) v1.Silo {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		var cur v1.Silo
		for {
			if err := c.Get(ctx, "Silo", "dev", "box", &cur); err != nil {
				t.Fatal(err)
			}
			status, reason, ok := policyApplied(cur)
			id := kri.ID{Namespace: cur.Namespace, Name: cur.Name, UID: cur.UID}
			if ok && status == wantStatus && reason == wantReason && (host == "" || strings.Contains(h.Policy(id), `host: "`+host+`"`)) {
				return cur
			}
			if time.Now().After(deadline) {
				t.Fatalf("PolicyApplied status=%s reason=%s, want %s/%s host %q\npolicy:\n%s\n%s",
					status, reason, wantStatus, wantReason, host, h.Policy(id), h.Commands())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	wait(string(meta.ConditionTrue), "Applied", "api.github.com")
	h.FailOn("policy set")
	for attempt := 0; ; attempt++ {
		var cur v1.Grant
		if err := c.Get(ctx, "Grant", "dev", "web", &cur); err != nil {
			t.Fatal(err)
		}
		cur.Spec.Egress = []v1.EgressRule{{To: "api.gitlab.com"}}
		err := c.Update(ctx, &cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) || attempt > 20 {
			t.Fatal(err)
		}
	}
	wait(string(meta.ConditionFalse), "NotApplied", "")
	h.FailOn("")
	wait(string(meta.ConditionTrue), "Applied", "api.gitlab.com")
}

// A sandbox is created with the silo's grants already in the policy file --policy names.
// A silo with no grants is created with no network (deny-all). A grant added while the silo
// is not being started is the policy the sandbox is created with.
func TestASandboxIsBornWithTheSilosGrants(t *testing.T) {
	deny := openshell.PolicyYAML(kri.Policy{})
	if got := bornPolicy(t, nil); got != deny || strings.Contains(got, "network_policies") {
		t.Fatalf("a silo with no grants was not deny-all:\n%s", got)
	}
	got := bornPolicy(t, []v1.EgressRule{{To: "api.github.com"}})
	if !strings.Contains(got, "network_policies:") || !strings.Contains(got, `host: "api.github.com"`) {
		t.Fatalf("sandbox create did not carry the silo's grants:\n%s", got)
	}
	got = bornWhenTheGrantArrives(t)
	if !strings.Contains(got, `host: "api.gitlab.com"`) || strings.Contains(got, "api.github.com") {
		t.Fatalf("a grant added while the silo was not started was not the policy it was created with:\n%s", got)
	}
}
