package integration

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controlplane"
	"kevaso.com/core/internal/transfer"
	"kevaso.com/core/internal/worker"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// Streams end to end on the path the machines use, with nothing left out: the real control plane
// (controlplane.Start: its stamping middleware on every answer), a worker joined as `kevasod
// worker` joins (the failover client, with its control-plane judge, agent.Watermark, set before
// anything uses it), its agent's tunnel to the control plane, and kvo's client (a user
// certificate, the failover client of a kvo context). An exec, a copy (what kvo cp runs) and a
// terminal session go through the tunnel.
//
// The other stream tests (TestKvoExec and the like) serve the API server without the stamping
// middleware and give the agent client.New (no failover, no judge): an upgrade's answer that lost
// its stamp, judged NotYet by a worker's judge, refused every tunnel on the machines while they
// stayed green.
func TestStreamsThroughAJudgedTunnelEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvs")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	cp, err := controlplane.Start(ctx, controlplane.Config{Create: true, ClusterName: "it", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: sock, Heartbeat: 100 * time.Millisecond, HostLease: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	admin := client.NewUnix(sock)
	server := "https://" + cp.APIAddr
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	// The silo's runtime: exec answers with its command; tar (what a copy runs) with a real tar
	// of one file.
	rt := fake.New()
	rt.Handler = func(id kri.ID, cmd []string, stdin []byte) (string, int) {
		if len(cmd) > 1 && cmd[0] == "tar" && cmd[1] == "-cf" {
			var b bytes.Buffer
			tw := tar.NewWriter(&b)
			body := "hello from " + id.Name + "\n"
			_ = tw.WriteHeader(&tar.Header{Name: "./hostname", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
			_, _ = tw.Write([]byte(body))
			_ = tw.Close()
			return b.String(), 0
		}
		return strings.Join(cmd, " ") + " in " + id.Name, 0
	}

	// The worker, as kevasod worker sets it up: joined, its judge on the client before any use.
	must(admin.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "w1"},
		Spec: v1.HostSpec{InternalIP: "127.0.0.2", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "cloud-hypervisor"}}}}}}))
	wdir := filepath.Join(dir, "w1")
	must(os.MkdirAll(wdir, 0o700))
	must(os.WriteFile(filepath.Join(wdir, "ca.crt"), cp.CA.PEM, 0o644))
	var tok client.JoinTokenResponse
	must(admin.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: "w1", Roles: []string{"worker"}}, &tok))
	must(os.WriteFile(filepath.Join(wdir, "join-token"), []byte(tok.Token), 0o600))
	wc, err := worker.Join(ctx, worker.JoinConfig{HostName: "w1", Server: server, CAFile: filepath.Join(wdir, "ca.crt"), TokenFile: filepath.Join(wdir, "join-token"), DataDir: wdir})
	must(err)
	wm := agent.OpenWatermark(filepath.Join(wdir, "control-plane-watermark.json"), t.Logf)
	wc.ControlPlane = wm
	contact := &worker.Contact{}
	cfg := worker.Config{HostName: "w1", Runtimes: []string{"cloud-hypervisor"}, DataDir: wdir, Clock: clock.Real{}, Log: t.Logf, Contact: contact, Watermark: wm}
	go worker.Heartbeat(ctx, wc, "w1", 100*time.Millisecond, clock.Real{}, func(string, ...any) {}, contact)
	go worker.Run(ctx, wc, cfg, map[string]worker.Installer{"cloud-hypervisor": fakeInstaller{rt}})

	// kvo, as a kvo context makes its client.
	key, csr, err := client.NewKeyAndCSR("ops")
	must(err)
	cert, ca, err := admin.SignUserCSR(ctx, "ops", csr)
	must(err)
	kvo, err := client.NewTLSEndpoints([]string{server}, ca, cert, key)
	must(err)

	must(kvo.Create(ctx, ns("demo")))
	must(kvo.Create(ctx, silo("hello", "demo")))
	waitSilo(t, ctx, admin, "hello", func(s *v1.Silo) bool { return s.Status.Host == "w1" && s.Status.Phase == "Running" })

	// exec (kvo exec): retried only while the tunnel is still coming up.
	var out, errs bytes.Buffer
	for {
		out.Reset()
		errs.Reset()
		code, err := kvo.Exec(ctx, "demo", "hello", []string{"echo", "hi"}, nil, &out, &errs)
		if err != nil && strings.Contains(err.Error(), "HostNotConnected") && ctx.Err() == nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err != nil || code != 0 || out.String() != "echo hi in hello" {
			t.Fatalf("exec: %v, exit %d, %q %q (the watermark: %+v)", err, code, out.String(), errs.String(), wmState(wm))
		}
		break
	}

	// A copy out of the silo (kvo cp hello:/etc/hostname .).
	var tarred bytes.Buffer
	must((transfer.Silo{C: kvo, Namespace: "demo", Name: "hello"}).ReadTar(ctx, "/etc/hostname", &tarred))
	tr := tar.NewReader(&tarred)
	hdr, err := tr.Next()
	must(err)
	body, _ := io.ReadAll(tr)
	if hdr.Name != "./hostname" || string(body) != "hello from hello\n" {
		t.Fatalf("copy: %q %q", hdr.Name, body)
	}

	// A terminal session (kvo exec -t / kvo ssh's path).
	s, err := kvo.OpenExec(ctx, "demo", "hello", client.ExecRequest{Command: []string{"echo", "tty"}, TTY: true, Rows: 24, Cols: 80})
	must(err)
	go s.SendStdin(nil)
	out.Reset()
	code, err := s.Wait(&out, &out)
	_ = s.Close()
	if err != nil || code != 0 || !strings.Contains(out.String(), "echo tty in hello") {
		t.Fatalf("terminal: %v, exit %d, %q", err, code, out.String())
	}
	if wm.Held() {
		t.Fatalf("the worker holds: %+v", wmState(wm))
	}
}

func wmState(wm *agent.Watermark) string {
	if wm.Held() {
		return "held"
	}
	return "not held"
}
