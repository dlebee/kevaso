package integration

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controlplane"
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
	cp, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", Address: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
	server := "https://" + cp.APIAddr

	// What kvoadm host add does: the Host object, then a join token for it.
	if err := admin.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "worker-1"},
		Spec: v1.HostSpec{Address: "127.0.0.2", Region: "ca-central",
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
	go worker.Heartbeat(ctx, c, "worker-1", 100*time.Millisecond, clock.Real{}, t.Logf)
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
