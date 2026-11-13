//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed"
)

// echoServer answers GET with "NAME PYTHON-VERSION FIRST-BOOT": which instance, which image, and
// what its volume remembers from its first boot.
const echoServer = `import http.server, os, platform
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        first = open("/data/first").read().strip()
        b = f"{os.uname().nodename} {platform.python_version()} {first}\n".encode()
        self.send_response(200); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.HTTPServer(("", 8080), H).serve_forever()
`

// TestSiloSetsAndServices is M12 on real machines (example 07 without the cloud): a SiloSet of
// containers from a registry reference (python 3.12), a SiloSet of two instances spread over two hosts, and a Service in front of them,
// reached by name from a client silo through its virtual IP, on this host and across the mesh;
// a silo its endpoints don't allow is refused. Then a rolling upgrade to python 3.13 (a new
// reference in the set) that keeps each
// instance's volume, a scale-in that asks first, and a reset.
//
//	a  control plane + worker (docker)
//	b  worker (docker)
func TestSiloSetsAndServices(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	d, arch := driver(t)
	sshd, ok := d.(testbed.SSHAccess)
	if !ok {
		t.Skip("needs a driver with SSH access (Lima)")
	}
	if os.Getenv("LIMA_HOME") == "" {
		real, _ := os.UserHomeDir()
		t.Setenv("LIMA_HOME", filepath.Join(real, ".lima"))
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KVO_CONFIG", filepath.Join(home, ".kevaso", "config.yaml"))
	t.Setenv("KVO_TOKEN_STORE", "file")
	t.Setenv("KVO_SERVER", "")

	run := testbed.NewRunID()
	specs := map[string]testbed.Spec{
		"a": {Role: "a", CPUs: 2, Memory: "3GiB", Disk: "20GiB", Shared: true},
		"b": {Role: "b", CPUs: 2, Memory: "3GiB", Disk: "20GiB", Shared: true},
	}
	machines := map[string]testbed.Machine{}
	var mu sync.Mutex
	t.Cleanup(func() {
		if os.Getenv("KEVASO_E2E_KEEP") != "" {
			t.Logf("KEEPING the run's machines (limactl list | grep %s)", run)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for _, s := range specs {
			m := testbed.Machine{Name: testbed.MachineName(run, s.Role), Run: run, Role: s.Role}
			if err := d.Delete(ctx, m); err != nil {
				t.Errorf("teardown %s: %v", m.Name, err)
			}
		}
	})
	var wg sync.WaitGroup
	errs := make(chan error, len(specs))
	for name, s := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := d.Create(ctx, run, s)
			if err != nil {
				errs <- fmt.Errorf("create %s: %w", name, err)
				return
			}
			mu.Lock()
			machines[name] = m
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	sh := func(name, cmd string) (string, error) { return d.Exec(ctx, machines[name], "sudo", "sh", "-c", cmd) }
	addrOf := func(name string) string {
		out, err := sh(name, `ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1`)
		if err != nil || strings.TrimSpace(out) == "" {
			t.Fatalf("%s's address: %q %v", name, out, err)
		}
		return strings.TrimSpace(out)
	}
	aIP, bIP := addrOf("a"), addrOf("b")

	bin := filepath.Join(t.TempDir(), "kevasod")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	type cmd func(context.Context, []string, io.Reader, io.Writer, io.Writer) int
	must := func(f cmd, stdin string, args ...string) string {
		t.Helper()
		var o, e bytes.Buffer
		if code := f(ctx, args, strings.NewReader(stdin), &o, &e); code != 0 {
			t.Fatalf("%v: exit %d\n%s%s", args, code, o.String(), e.String())
		}
		return o.String()
	}
	sshArgs := func(name string) []string {
		info, err := sshd.SSH(ctx, machines[name])
		if err != nil {
			t.Fatal(err)
		}
		out, err := d.Exec(ctx, machines[name], "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub")
		if err != nil {
			t.Fatal(err)
		}
		return []string{info.User + "@" + info.Host, "--ssh-port", strconv.Itoa(info.Port), "--ssh-key", info.KeyFile,
			"--host-key", strings.Fields(out)[1], "--kevasod", bin}
	}
	t.Logf("%s", must(kvoadm.Run, "", append(append([]string{"init"}, sshArgs("a")...),
		"--name", "a", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--internal-ip", aIP, "--worker", "--runtime", "docker")...))
	t.Logf("%s", must(kvoadm.Run, "", append(append([]string{"host", "add"}, sshArgs("b")...),
		"--name", "b", "--install", "worker", "--runtime", "docker", "--internal-ip", bIP, "--server", "https://"+aIP+":6443")...))

	// Both workers' docker Ready first: spread is a preference, and a placed silo never moves.
	for deadline := time.Now().Add(15 * time.Minute); ; {
		var o, e bytes.Buffer
		kvo.Run(ctx, []string{"get", "hosts", "-o", "json"}, nil, &o, &e)
		hs := parseHosts(t, o.Bytes())
		ready := len(hs) == 2
		for _, h := range hs {
			ready = ready && h.Status.Runtimes["docker"].State == "Ready"
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("docker never Ready on both hosts:\n%s", must(kvo.Run, "", "get", "hosts"))
		}
		time.Sleep(5 * time.Second)
	}

	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	py := func(v string) string { return "docker.io/library/python:" + v + "-slim" }
	objs := []any{
		v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "web3"}},
		v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "echo", Namespace: "web3"},
			Spec: v1.SiloSetSpec{Image: py("3.12"), Instances: 2, Spread: "host", UpgradePolicy: v1.UpgradeRolling,
				Template: v1.SiloTemplate{Labels: map[string]string{"app": "echo"}, SiloSpec: v1.SiloSpec{
					Runtime: "docker", Resources: v1.Resources{Memory: "256Mi"},
					Command: []string{"python3", "-c", echoServer},
					Volumes: []v1.Volume{{Name: "data", MountPath: "/data"}},
					Init:    &v1.Init{Steps: []v1.InitStep{{Name: "first", Run: "test -s /data/first || date +%s%N > /data/first"}}},
					Ports:   []v1.SiloPort{{Name: "http", Port: 8080}},
					Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", AllowFrom: []string{"client"}}}, RouteWhen: v1.RouteWhenReady},
					Probes:  &v1.Probes{Readiness: &v1.Probe{HTTP: &v1.HTTPProbe{Port: "http"}, Period: "3s"}},
				}}}},
		v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "echo", Namespace: "web3"},
			Spec: v1.ServiceSpec{Selector: map[string]string{"app": "echo"}, Ports: []v1.ServicePortSpec{{Name: "http", Port: 80, TargetPort: "http"}}, RouteWhen: v1.RouteWhenReady}},
	}
	for _, n := range []string{"client", "stranger"} {
		objs = append(objs, v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: n, Namespace: "web3"},
			Spec: v1.SiloSpec{Runtime: "docker", Image: py("3.12"), Command: []string{"sleep", "infinity"}, Resources: v1.Resources{Memory: "128Mi"}}})
	}
	var docs []string
	for _, o := range objs {
		b, _ := json.Marshal(o)
		docs = append(docs, string(b))
	}
	must(kvo.Run, strings.Join(docs, "\n---\n"), "apply", "-f", "-")

	getJSON := func(out any, args ...string) {
		t.Helper()
		var o, e bytes.Buffer
		if code := kvo.Run(ctx, append(args, "-n", "web3", "-o", "json"), nil, &o, &e); code != 0 {
			t.Fatalf("%v: %s", args, e.String())
		}
		if err := json.Unmarshal(o.Bytes(), out); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	waitFor := func(what string, limit time.Duration, cond func() (bool, string)) {
		t.Helper()
		deadline := time.Now().Add(limit)
		last := ""
		for i := 0; ; i++ {
			ok, s := cond()
			if ok {
				t.Logf("%s: ok", what)
				return
			}
			last = s
			if i%10 == 9 {
				t.Logf("%s: still waiting: %s", what, s)
			}
			if time.Now().After(deadline) {
				out, _ := kvoRun(ctx, "", "get", "silos", "-n", "web3")
				j, _ := sh("a", "journalctl -u kevasod -n 60 --no-pager | grep -v 'retry in' | tail -30")
				t.Fatalf("%s: never happened; last: %s\nsilos:\n%s\nkevasod on a:\n%s", what, last, out, j)
			}
			time.Sleep(5 * time.Second)
		}
	}
	silo := func(name string) *v1.Silo {
		var s v1.Silo
		getJSON(&s, "get", "silo", name)
		return &s
	}
	waitFor("the set's instances Ready on both hosts, the clients running", 20*time.Minute, func() (bool, string) {
		out, _ := kvoRun(ctx, "", "get", "silos", "-n", "web3")
		if strings.Count(out, "Running") < 4 {
			return false, out
		}
		e0, e1 := silo("echo-0"), silo("echo-1")
		return meta.IsTrue(e0.Status.Conditions, "Ready") && meta.IsTrue(e1.Status.Conditions, "Ready") && e0.Status.Host != e1.Status.Host, out
	})
	t.Logf("kvo get silosets,services:\n%s%s", must(kvo.Run, "", "get", "silosets", "-n", "web3"), must(kvo.Run, "", "get", "services", "-n", "web3"))

	in := func(s, script string) string {
		var o bytes.Buffer
		kvo.Run(ctx, []string{"exec", "silo", s, "-n", "web3", "--", "python3", "-c", script}, nil, &o, &o)
		return strings.TrimSpace(o.String())
	}
	get := `import urllib.request, sys
try: print(urllib.request.urlopen("http://echo.web3.kevaso/", timeout=5).read().decode().strip())
except Exception as e: print("error", e)`
	ask := func(from string, n int) map[string]string { // instance → its answer
		seen := map[string]string{}
		for i := 0; i < n; i++ {
			if f := strings.Fields(in(from, get)); len(f) == 3 {
				seen[f[0]] = f[1] + " " + f[2]
			} else {
				seen["error"] = strings.Join(f, " ")
			}
		}
		return seen
	}
	var firsts map[string]string
	waitFor("the client reaches both instances through the service (one is on the other host)", 3*time.Minute, func() (bool, string) {
		seen := ask("client", 16)
		firsts = seen
		return strings.HasPrefix(seen["echo-0"], "3.12") && strings.HasPrefix(seen["echo-1"], "3.12"), fmt.Sprint(seen)
	})
	if got := in("stranger", get); !strings.HasPrefix(got, "error") {
		t.Errorf("a silo the endpoints don't allow got through the service: %q", got)
	}
	var svc v1.Service
	getJSON(&svc, "get", "service", "echo")
	if svc.Status.ClusterIP == "" || len(svc.Status.Endpoints) != 2 {
		t.Fatalf("service status: %+v", svc.Status)
	}

	// A new reference, rolling: each instance reset onto python 3.13, its volume (first boot) kept.
	var set v1.SiloSet
	getJSON(&set, "get", "siloset", "echo")
	set.Spec.Image = py("3.13")
	b, _ := json.Marshal(set)
	must(kvo.Run, string(b), "apply", "-f", "-")
	waitFor("every instance on python 3.13 with its volume", 15*time.Minute, func() (bool, string) {
		seen := ask("client", 16)
		var st v1.SiloSet
		getJSON(&st, "get", "siloset", "echo")
		ok := st.Status.Updated == 2 && st.Status.Ready == 2
		for _, n := range []string{"echo-0", "echo-1"} {
			ok = ok && strings.HasPrefix(seen[n], "3.13") && strings.Fields(seen[n])[1] == strings.Fields(firsts[n])[1]
		}
		return ok, fmt.Sprintf("%v (first boot was %v) set %d/%d updated", seen, firsts, st.Status.Updated, st.Status.Ready)
	})

	// Scaling in deletes disks: it says which and wants --yes.
	var o, e bytes.Buffer
	if code := kvo.Run(ctx, []string{"scale", "siloset", "echo", "--instances", "1", "-n", "web3"}, nil, &o, &e); code == 0 || !strings.Contains(e.String(), "echo-1") {
		t.Fatalf("scale in without --yes: %d %s%s", code, o.String(), e.String())
	}
	must(kvo.Run, "", "scale", "siloset", "echo", "--instances", "1", "--yes", "-n", "web3")
	waitFor("one instance left, the service following", 5*time.Minute, func() (bool, string) {
		var s v1.Service
		getJSON(&s, "get", "service", "echo")
		out, _ := kvoRun(ctx, "", "get", "silos", "-n", "web3")
		return len(s.Status.Endpoints) == 1 && !strings.Contains(out, "echo-1"), out
	})

	// A reset: the same image, a fresh container, the volume kept.
	must(kvo.Run, "", "reset", "silo", "echo-0", "-n", "web3")
	waitFor("echo-0 reset, its volume kept", 5*time.Minute, func() (bool, string) {
		s := silo("echo-0")
		c := meta.FindCondition(s.Status.Conditions, "Updated")
		seen := ask("client", 2)
		return c != nil && c.Reason == "Reset" && meta.IsTrue(s.Status.Conditions, "Ready") && s.Status.Image.Reset == s.Spec.Reset &&
			len(strings.Fields(seen["echo-0"])) == 2 && strings.Fields(seen["echo-0"])[1] == strings.Fields(firsts["echo-0"])[1], fmt.Sprint(seen)
	})
	t.Logf("kvo describe siloset echo:\n%s", must(kvo.Run, "", "describe", "siloset", "echo", "-n", "web3"))
	t.Logf("kvo describe service echo:\n%s", must(kvo.Run, "", "describe", "service", "echo", "-n", "web3"))
}
