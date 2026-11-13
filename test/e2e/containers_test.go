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

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/container"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/testbed"
)

// TestContainerSilos is M9 on real machines: docker and podman silos on the host's silo bridge, so
// everything the VMs have applies to them: init containers before the main one, a volume that
// outlives a restart, exposure on the host's address with the client's IP kept, default-deny egress,
// the egress gate injecting a key, and the broker over a socket of their own.
//
//	metal-1  control plane + worker with docker and podman (no KVM needed)
//	client   "the internet": HTTPS for api.*, other.* (names from sslip.io)
func TestContainerSilos(t *testing.T) {
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
	t.Setenv("KVO_SERVER", "")

	run := testbed.NewRunID()
	specs := map[string]testbed.Spec{
		"metal":  {Role: "metal", CPUs: 4, Memory: "4GiB", Disk: "30GiB", Shared: true},
		"client": {Role: "client", CPUs: 1, Memory: "1GiB", Disk: "10GiB", Shared: true},
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
			_ = d.Delete(ctx, testbed.Machine{Name: testbed.MachineName(run, s.Role), Run: run, Role: s.Role})
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
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(out)
	}
	metalIP, clientIP := addrOf("metal"), addrOf("client")
	zone := strings.ReplaceAll(clientIP, ".", "-") + ".sslip.io"
	apiHost, otherHost := "api."+zone, "other."+zone
	t.Logf("metal-1 %s, client %s (%s)", metalIP, clientIP, zone)
	setup := strings.ReplaceAll(inetSetup, "DNS:api.allowed.test,DNS:pass.test,DNS:other.blocked.test", "DNS:"+apiHost+",DNS:"+otherHost)
	caOut, err := sh("client", setup)
	if err != nil {
		t.Fatalf("internet: %v\n%s", err, caOut)
	}
	inetCA := caOut[strings.Index(caOut, "-----BEGIN CERTIFICATE-----"):]
	if _, err := sh("metal", fmt.Sprintf("mkdir -p /etc/kevaso && printf '%%s' '%s' > /etc/kevaso/test-internet-ca.pem", strings.TrimSpace(inetCA))); err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	bin, hget := filepath.Join(tmp, "kevasod"), filepath.Join(tmp, "hget")
	_ = os.WriteFile(filepath.Join(tmp, "hget.go"), []byte(hgetGo), 0o644)
	for _, b := range [][]string{{"-o", bin, "kevaso.com/core/cmd/kevasod"}, {"-ldflags", "-s -w", "-o", hget, filepath.Join(tmp, "hget.go")}} {
		build := exec.CommandContext(ctx, "go", append([]string{"build"}, b...)...)
		build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %v: %v\n%s", b, err, out)
		}
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
	info, err := sshd.SSH(ctx, machines["metal"])
	if err != nil {
		t.Fatal(err)
	}
	hk, _ := d.Exec(ctx, machines["metal"], "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub")
	must(kvoadm.Run, "", "init", info.User+"@"+info.Host, "--ssh-port", strconv.Itoa(info.Port), "--ssh-key", info.KeyFile,
		"--host-key", strings.Fields(hk)[1], "--kevasod", bin, "--name", "metal-1", "--cluster", "e2e",
		"--api-server", "https://127.0.0.1:6443", "--address", metalIP, "--worker",
		"--runtime", "docker", "--runtime", "podman", "--egress-extra-ca", "/etc/kevaso/test-internet-ca.pem")

	apiKey, dbPassword := randomToken(t), randomToken(t)
	must(kvo.Run, "apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: shop }\n", "apply", "-f", "-")
	must(kvo.Run, apiKey, "create", "secret", "api-key", "-n", "shop", "--from-file", "-", "--allow", "inject", "--write-only")
	must(kvo.Run, dbPassword, "create", "secret", "db-password", "-n", "shop", "--from-file", "-")
	box := func(name, runtime string) string {
		return fmt.Sprintf(`---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: %[1]s, namespace: shop }
spec:
  runtime: %[2]s
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 512Mi }
  volumes: [{ name: data, mountPath: /data }]
  grants: [app]
  init:
    steps:
      - name: first
        run: echo "made by an init container of %[1]s" > /data/marker
      - name: second
        run: test -s /data/marker && hostname > /data/host
`, name, runtime)
	}
	manifest := `apiVersion: kevaso/v1
kind: Grant
metadata: { name: app, namespace: shop }
spec:
  secrets:
    - { name: api-key, deliver: inject, to: { host: ` + apiHost + ` } }
    - { name: db-password }
` + box("dk", "docker") + box("pm", "podman") + `---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: web, namespace: shop }
spec:
  runtime: docker
  image: docker.io/library/python:3.12-slim
  command: [python3, -m, http.server, "8080"]
  service:
    ports: [{ name: http, port: 8080 }]
    expose: hostPort
`
	must(kvo.Run, manifest, "apply", "-f", "-")
	deadline := time.Now().Add(25 * time.Minute)
	waited := 0
	for {
		out, code := kvoRun(ctx, "", "get", "silos", "-n", "shop")
		if code == 0 && strings.Count(out, "Running") == 3 {
			t.Logf("silos:\n%s", out)
			break
		}
		if waited++; waited%12 == 0 {
			t.Logf("still waiting:\n%s", out)
		}
		if time.Now().After(deadline) || strings.Contains(out, "Failed") {
			j, _ := sh("metal", "journalctl -u kevasod -n 80 --no-pager | grep -v 'retry in' | tail -40")
			for _, s := range []string{"dk", "pm", "web"} {
				desc, _ := kvoRun(ctx, "", "describe", "silo", s, "-n", "shop")
				t.Log(desc)
			}
			t.Fatalf("silos:\n%s\nkevasod:\n%s", out, j)
		}
		time.Sleep(10 * time.Second)
	}

	hgetBin, _ := os.ReadFile(hget)
	guestBin, _ := os.ReadFile(bin)
	in := func(silo, script string) string {
		var o bytes.Buffer
		kvo.Run(ctx, []string{"exec", "silo", silo, "-n", "shop", "--", "sh", "-c", script}, nil, &o, &o)
		return strings.TrimSpace(o.String())
	}
	expect := func(what, got, want string) {
		t.Helper()
		if !strings.Contains(got, want) {
			t.Errorf("%s: got %q, want %q", what, got, want)
		} else {
			t.Logf("%s: ok", what)
		}
	}
	for _, s := range []string{"dk", "pm"} {
		t.Run(s, func(t *testing.T) {
			expect("init containers ran first, in order, on the volume", in(s, "cat /data/marker /data/host"), "made by an init container of "+s+"\n"+s)
			var o, e bytes.Buffer
			if code := kvo.Run(ctx, []string{"exec", "silo", s, "-n", "shop", "--", "sh", "-c", "cat > /data/hget && chmod +x /data/hget"}, bytes.NewReader(hgetBin), &o, &e); code != 0 {
				t.Fatalf("upload: %d %s", code, e.String())
			}
			// Nothing of Kevaso's is in a user's container: it brings its own broker client (here,
			// kvo-guest itself, copied in like any program).
			if got := in(s, "command -v kvo-guest || echo none"); got != "none" {
				t.Errorf("kvo-guest is in a user's container: %q", got)
			}
			o.Reset()
			e.Reset()
			if code := kvo.Run(ctx, []string{"exec", "silo", s, "-n", "shop", "--", "sh", "-c", "cat > /data/kvo-guest && chmod +x /data/kvo-guest"}, bytes.NewReader(guestBin), &o, &e); code != 0 {
				t.Fatalf("upload kvo-guest: %d %s", code, e.String())
			}
			expect("the egress gate injects the key", in(s, "/data/hget https://"+apiHost+"/v1"), `"auth": "`+authHash("Bearer "+apiKey)+`"`)
			if got := in(s, "/data/hget https://"+otherHost+"/"); strings.Contains(got, `"host"`) {
				t.Errorf("a host no grant names answered: %q", got)
			}
			expect("default deny (plain HTTP out)", in(s, "/data/hget http://"+clientIP+":80/ 2>&1 | head -c 200"), "error")
			expect("broker over the container's own socket", in(s, "/data/kvo-guest secret get db-password"), dbPassword)
			if got := in(s, "/data/kvo-guest secret get api-key"); !strings.Contains(got, "no secret") {
				t.Errorf("an inject-only key reached the container: %q", got)
			}
			if n := in(s, fmt.Sprintf("grep -rl -F -e '%s' / --exclude-dir=proc --exclude-dir=sys 2>/dev/null | wc -l", apiKey)); n != "0" {
				t.Errorf("the injected key is in the container's files: %s", n)
			}
		})
	}

	// A restart keeps the volume: stop the main container behind Kevaso's back; the agent starts it again.
	var dk v1.Silo
	if err := json.Unmarshal([]byte(must(kvo.Run, "", "get", "silo", "dk", "-n", "shop", "-o", "json")), &dk); err != nil {
		t.Fatal(err)
	}
	main := container.NamesFor(kri.ID{Namespace: dk.Namespace, Name: dk.Name, UID: dk.UID}).Main
	if _, err := sh("metal", "docker stop -t 2 "+main); err != nil {
		t.Fatal(err)
	}
	restarted := false
	for i := 0; i < 30 && !restarted; i++ {
		time.Sleep(3 * time.Second)
		st, _ := sh("metal", "docker inspect --format '{{.State.Status}} {{.State.StartedAt}}' "+main)
		restarted = strings.HasPrefix(st, "running")
	}
	if !restarted {
		t.Fatal("the agent didn't start the stopped container again")
	}
	expect("after a restart the volume is still there", in("dk", "cat /data/marker"), "made by an init container of dk")

	// Exposure on the host's address: the client reaches the web silo, which sees the client's IP.
	got, _ := sh("client", "curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://"+metalIP+":8080/")
	expect("hostPort from the internet", got, "200")
	logs, _ := sh("metal", "docker logs "+container.NamesFor(kri.ID{Namespace: "shop", Name: "web", UID: uid(t, "web")}).Main+" 2>&1 | tail -3")
	expect("the silo sees the client's own address", logs, clientIP)
}

func uid(t *testing.T, silo string) string {
	var o bytes.Buffer
	kvo.Run(context.Background(), []string{"get", "silo", silo, "-n", "shop", "-o", "json"}, nil, &o, io.Discard)
	var s v1.Silo
	if err := json.Unmarshal(o.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	return s.UID
}
