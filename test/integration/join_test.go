package integration

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	silocontroller "kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/controlplane"
	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/worker"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// fakeInstaller is a runtime with nothing to install.
type fakeInstaller struct{ *fake.Runtime }

func (fakeInstaller) Install(context.Context, func(string)) error { return nil }

// Example 02 in one process: a control plane that runs no silos, and a worker-only host that joins
// with a one-time token over TLS, reports, and runs the silo placed on it.
func TestAWorkerOnlyHostJoinsAndRunsSilos(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvj")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cp, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
	server := "https://" + cp.APIAddr

	// What kvoadm host add does: the Host object, then a join token for it.
	if err := admin.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "worker-1"},
		Spec: v1.HostSpec{InternalIP: "127.0.0.2", Region: "ca-central",
			Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "cloud-hypervisor"}}}}}}); err != nil {
		t.Fatal(err)
	}
	var tok client.JoinTokenResponse
	if err := admin.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: "worker-1", Roles: []string{"worker"}}, &tok); err != nil {
		t.Fatal(err)
	}
	if err := admin.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: "x", Roles: []string{"control-plane"}}, nil); err == nil {
		t.Error("a control-plane join token was issued")
	}

	// The worker host: its files, as kvoadm uploads them.
	wdir := filepath.Join(dir, "w")
	_ = os.MkdirAll(wdir, 0o700)
	_ = os.WriteFile(filepath.Join(wdir, "ca.crt"), cp.CA.PEM, 0o644)
	_ = os.WriteFile(filepath.Join(wdir, "join-token"), []byte(tok.Token), 0o600)
	jc := worker.JoinConfig{HostName: "worker-1", Server: server, CAFile: filepath.Join(wdir, "ca.crt"),
		TokenFile: filepath.Join(wdir, "join-token"), DataDir: wdir}
	c, err := worker.Join(ctx, jc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(jc.TokenFile); !os.IsNotExist(err) {
		t.Error("the join token is still on disk after joining")
	}
	var me client.WhoAmI
	if err := c.Call(ctx, http.MethodGet, "/auth/whoami", nil, &me); err != nil || me.Type != "host" || me.Name != "worker-1" || me.Role != "worker" {
		t.Fatalf("whoami: %+v %v", me, err)
	}
	if _, err := worker.Join(ctx, jc); err != nil { // a restart reuses the certificate
		t.Fatalf("rejoin: %v", err)
	}

	rt := fake.New()
	rt.Handler = func(kri.ID, []string, []byte) (string, int) { return "", 0 }
	wc := worker.Config{HostName: "worker-1", Runtimes: []string{"cloud-hypervisor"}, DataDir: wdir, Clock: clock.Real{}, Log: t.Logf}
	go worker.Heartbeat(ctx, c, "worker-1", 100*time.Millisecond, clock.Real{}, t.Logf, nil)
	go worker.Run(ctx, c, wc, map[string]worker.Installer{"cloud-hypervisor": fakeInstaller{rt}})

	_ = admin.Create(ctx, ns("demo"))
	if err := admin.Create(ctx, silo("hello", "demo")); err != nil {
		t.Fatal(err)
	}
	for {
		var s v1.Silo
		_ = admin.Get(ctx, "Silo", "demo", "hello", &s)
		if s.Status.Phase == "Running" {
			if s.Status.Host != "worker-1" {
				t.Fatalf("ran on %s", s.Status.Host)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("silo never ran: %+v", s.Status)
		case <-time.After(50 * time.Millisecond):
		}
	}
	// And kvo exec reaches it through the worker's own TLS tunnel.
	if code, err := admin.Exec(ctx, "demo", "hello", []string{"true"}, nil, nil, nil); err != nil || code != 0 {
		t.Fatalf("exec on the worker: %d %v", code, err)
	}
}

type testWorker struct {
	name   string
	rt     *fake.Runtime
	cancel context.CancelFunc
}

// joinWorker does what kvoadm host add and kevasod worker do, in-process.
func joinWorker(t *testing.T, ctx context.Context, admin *client.Client, server string, caPEM []byte, dir, name string, rt *fake.Runtime) *testWorker {
	t.Helper()
	if err := admin.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
		Spec: v1.HostSpec{InternalIP: "127.0.0.2", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "cloud-hypervisor"}}}}}}); err != nil && !client.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	wdir := filepath.Join(dir, name)
	_ = os.MkdirAll(wdir, 0o700)
	_ = os.WriteFile(filepath.Join(wdir, "ca.crt"), caPEM, 0o644)
	if _, err := os.Stat(filepath.Join(wdir, "pki", "host.crt")); err != nil {
		var tok client.JoinTokenResponse
		if err := admin.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: name, Roles: []string{"worker"}}, &tok); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(wdir, "join-token"), []byte(tok.Token), 0o600)
	}
	c, err := worker.Join(ctx, worker.JoinConfig{HostName: name, Server: server, CAFile: filepath.Join(wdir, "ca.crt"), TokenFile: filepath.Join(wdir, "join-token"), DataDir: wdir})
	if err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithCancel(ctx)
	wc := worker.Config{HostName: name, Runtimes: []string{"cloud-hypervisor"}, DataDir: wdir, Clock: clock.Real{}, Log: func(string, ...any) {}}
	go worker.Heartbeat(wctx, c, name, 100*time.Millisecond, clock.Real{}, func(string, ...any) {}, nil)
	go worker.Run(wctx, c, wc, map[string]worker.Installer{"cloud-hypervisor": fakeInstaller{rt}})
	return &testWorker{name: name, rt: rt, cancel: cancel}
}

func waitSilo(t *testing.T, ctx context.Context, c *client.Client, name string, ok func(*v1.Silo) bool) *v1.Silo {
	t.Helper()
	for {
		var s v1.Silo
		_ = c.Get(ctx, "Silo", "demo", name, &s)
		if ok(&s) {
			return &s
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: never got there: %+v", name, s.Status)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Losing a host: the Wait silo waits for it, the Recreate silo starts fresh elsewhere, and when the
// host comes back the Wait silo runs there again while the old copy of the other is removed.
func TestLosingAHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	saved := silocontroller.RecreateAfter
	silocontroller.RecreateAfter = time.Second
	defer func() { silocontroller.RecreateAfter = saved }()
	dir, _ := os.MkdirTemp("/tmp", "kvl")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cp, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"),
		Heartbeat: 100 * time.Millisecond, HostLease: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
	server := "https://" + cp.APIAddr
	handler := func(kri.ID, []string, []byte) (string, int) { return "", 0 }
	rt1 := fake.New()
	rt1.Handler = handler
	w1 := joinWorker(t, ctx, admin, server, cp.CA.PEM, dir, "w1", rt1)

	_ = admin.Create(ctx, ns("demo"))
	precious, stateless := silo("precious", "demo"), silo("stateless", "demo")
	stateless.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	for _, s := range []*v1.Silo{precious, stateless} {
		if err := admin.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		waitSilo(t, ctx, admin, s.Name, func(s *v1.Silo) bool { return s.Status.Phase == "Running" && s.Status.Host == "w1" })
	}
	rt2 := fake.New()
	rt2.Handler = handler
	joinWorker(t, ctx, admin, server, cp.CA.PEM, dir, "w2", rt2)

	// w1 goes dark.
	w1.cancel()
	waitSilo(t, ctx, admin, "precious", func(s *v1.Silo) bool {
		c := meta.FindCondition(s.Status.Conditions, "HostLost")
		return s.Status.Phase == "Unknown" && s.Status.Host == "w1" && c != nil && c.Reason == "Waiting"
	})
	got := waitSilo(t, ctx, admin, "stateless", func(s *v1.Silo) bool { return s.Status.Phase == "Running" && s.Status.Host == "w2" })
	if c := meta.FindCondition(got.Status.Conditions, "HostLost"); c == nil || c.Reason != "Recreated" {
		t.Fatalf("recreated without saying so: %+v", got.Status.Conditions)
	}

	// w1 comes back (same certificate, same runtime with its old VMs).
	joinWorker(t, ctx, admin, server, cp.CA.PEM, dir, "w1", rt1)
	waitSilo(t, ctx, admin, "precious", func(s *v1.Silo) bool {
		c := meta.FindCondition(s.Status.Conditions, "HostLost")
		return s.Status.Phase == "Running" && s.Status.Host == "w1" && c != nil && c.Status == meta.ConditionFalse
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		ids, _ := rt1.List(ctx)
		if len(ids) == 1 && ids[0].Name == "precious" {
			break // the stale copy of stateless is gone from w1
		}
		if time.Now().After(deadline) {
			t.Fatalf("w1 still has %v", ids)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// kvoadm host drain: cordon, move off the Recreate silo, leave (and name) the Wait one.
func TestDrainingAHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvd")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cp, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
	server := "https://" + cp.APIAddr
	cfgPath := filepath.Join(dir, "kvo.yaml")
	t.Setenv("KVO_CONFIG", cfgPath)
	key, csr, _ := client.NewKeyAndCSR("david")
	cert, ca, _ := admin.SignUserCSR(ctx, "david", csr)
	_ = kvoconfig.AddContext(cfgPath, "it", server, ca, cert, key)

	handler := func(kri.ID, []string, []byte) (string, int) { return "", 0 }
	rt1 := fake.New()
	rt1.Handler = handler
	joinWorker(t, ctx, admin, server, cp.CA.PEM, dir, "w1", rt1)
	_ = admin.Create(ctx, ns("demo"))
	precious, stateless := silo("precious", "demo"), silo("stateless", "demo")
	stateless.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	for _, s := range []*v1.Silo{precious, stateless} {
		_ = admin.Create(ctx, s)
		waitSilo(t, ctx, admin, s.Name, func(s *v1.Silo) bool { return s.Status.Phase == "Running" && s.Status.Host == "w1" })
	}
	rt2 := fake.New()
	rt2.Handler = handler
	joinWorker(t, ctx, admin, server, cp.CA.PEM, dir, "w2", rt2)

	out, errs, code := run(ctx, kvoadmCmd, "", "host", "drain", "w1")
	if code != 0 || !strings.Contains(out, "demo/stateless: recreated elsewhere") || !strings.Contains(out, "demo/precious stays: onHostLoss Wait") {
		t.Fatalf("drain: %d\n%s%s", code, out, errs)
	}
	waitSilo(t, ctx, admin, "stateless", func(s *v1.Silo) bool { return s.Status.Phase == "Running" && s.Status.Host == "w2" })
	if out, _, _ := run(ctx, kvoadmCmd, "", "host", "list"); !strings.Contains(out, "cordoned") {
		t.Fatalf("host list:\n%s", out)
	}
	// A new silo doesn't land on the cordoned host.
	_ = admin.Create(ctx, silo("new", "demo"))
	waitSilo(t, ctx, admin, "new", func(s *v1.Silo) bool { return s.Status.Host == "w2" })
	if _, _, code := run(ctx, kvoadmCmd, "", "host", "uncordon", "w1"); code != 0 {
		t.Fatal("uncordon")
	}
}
