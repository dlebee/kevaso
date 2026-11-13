//go:build e2e

package e2e

import (
	"bytes"
	"compress/gzip"
	"context"
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

	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed"
)

// hgetGo is a tiny HTTP client for the silos (OpenShell's default image has no curl or python):
// hget URL [HEADER=VALUE]… prints the status and body, or "error: …".
const hgetGo = `package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	req, _ := http.NewRequest("GET", os.Args[1], nil)
	for _, h := range os.Args[2:] {
		k, v, _ := strings.Cut(h, "=")
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(resp.StatusCode, string(b))
}
`

// TestOpenShellSilos is M8's "done when": an OpenShell silo with an injected key, on both drivers.
// One KVM host runs the openshell (VM) and openshell-container (Docker) runtimes, each sandbox under
// a gateway of its own user in a locked-down unit; a grant becomes OpenShell's policy (one name
// open, everything else refused) and a provider: the silo holds a placeholder, the real key is
// swapped in on the way out, and a rotation reaches the running silo.
//
//	metal-1  control plane + worker with openshell and openshell-container
//	client   "the internet": HTTPS for api.*, pass.* and other.* (names from sslip.io)
func TestOpenShellSilos(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Minute)
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
		"metal":  {Role: "metal", CPUs: 6, Memory: "8GiB", Disk: "40GiB", KVM: true, Shared: true},
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
	zone := strings.ReplaceAll(clientIP, ".", "-") + ".sslip.io" // public DNS: NAME.<ip>.sslip.io → ip
	apiHost, passHost, otherHost := "api."+zone, "pass."+zone, "other."+zone
	t.Logf("metal-1 %s, client %s (%s)", metalIP, clientIP, zone)

	setup := strings.ReplaceAll(inetSetup, "DNS:api.allowed.test,DNS:pass.test,DNS:other.blocked.test", "DNS:"+apiHost+",DNS:"+passHost+",DNS:"+otherHost)
	caOut, err := sh("client", setup)
	if err != nil {
		t.Fatalf("internet: %v\n%s", err, caOut)
	}
	inetCA := caOut[strings.Index(caOut, "-----BEGIN CERTIFICATE-----"):]
	if _, err := sh("metal", fmt.Sprintf("mkdir -p /etc/kevaso && printf '%%s' '%s' > /etc/kevaso/test-internet-ca.pem && chmod 0644 /etc/kevaso/test-internet-ca.pem", strings.TrimSpace(inetCA))); err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "kevasod")
	hget := filepath.Join(tmp, "hget")
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
		"--api-server", "https://127.0.0.1:6443", "--internal-ip", metalIP, "--worker",
		"--runtime", "openshell", "--runtime", "openshell-container", "--openshell-gateway-scope", "namespace",
		"--egress-extra-ca", "/etc/kevaso/test-internet-ca.pem")

	apiKey := randomToken(t)
	must(kvo.Run, "apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: agents }\n", "apply", "-f", "-")
	must(kvo.Run, apiKey, "create", "secret", "api-key", "-n", "agents", "--from-file", "-", "--allow", "inject", "--write-only")
	osSilo := func(name, runtime string) string {
		return fmt.Sprintf(`---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: %s, namespace: agents }
spec:
  runtime: %s
  container: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 1Gi }
  grants: [api]
`, name, runtime)
	}
	manifest := `apiVersion: kevaso/v1
kind: Grant
metadata: { name: api, namespace: agents }
spec:
  secrets:
    - { name: api-key, deliver: inject, env: API_KEY, to: { host: ` + apiHost + ` } }
  egress:
    - { to: ` + passHost + ` }
` + osSilo("vm", "openshell") + osSilo("ct", "openshell-container")
	must(kvo.Run, manifest, "apply", "-f", "-")

	deadline := time.Now().Add(35 * time.Minute)
	waited := 0
	for {
		out, code := kvoRun(ctx, "", "get", "silos", "-n", "agents")
		if code == 0 && strings.Count(out, "Running") == 2 {
			t.Logf("silos:\n%s", out)
			break
		}
		if waited++; waited%12 == 0 {
			h, _ := kvoRun(ctx, "", "describe", "host", "metal-1")
			t.Logf("still waiting:\n%s\n%s", out, h)
		}
		if time.Now().After(deadline) || strings.Contains(out, "Failed") {
			j, _ := sh("metal", "journalctl -u kevasod -n 80 --no-pager | grep -v 'retry in' | tail -40; journalctl -u 'kevaso-openshell-*' -n 40 --no-pager")
			for _, s := range []string{"vm", "ct"} {
				desc, _ := kvoRun(ctx, "", "describe", "silo", s, "-n", "agents")
				t.Log(desc)
			}
			t.Fatalf("silos:\n%s\nkevasod:\n%s", out, j)
		}
		time.Sleep(10 * time.Second)
	}

	// OpenShell takes at most 4 MiB of piped stdin: send the client compressed.
	raw, err := os.ReadFile(hget)
	if err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	hgetBin := gz.Bytes()
	for _, s := range []string{"vm", "ct"} {
		t.Run(s, func(t *testing.T) {
			in := func(script string) string {
				var o bytes.Buffer
				kvo.Run(ctx, []string{"exec", "silo", s, "-n", "agents", "--", "sh", "-c", script}, nil, &o, &o)
				return strings.TrimSpace(o.String())
			}
			var o, e bytes.Buffer
			if code := kvo.Run(ctx, []string{"exec", "silo", s, "-n", "agents", "--", "sh", "-c", "gunzip -c > /sandbox/hget && chmod +x /sandbox/hget"}, bytes.NewReader(hgetBin), &o, &e); code != 0 {
				t.Fatalf("upload hget: %d %s %s", code, o.String(), e.String())
			}
			desc := must(kvo.Run, "", "describe", "silo", s, "-n", "agents")
			if !strings.Contains(desc, "PolicyApplied") || strings.Contains(desc, "NotEnforceable") {
				t.Errorf("policy condition:\n%s", desc)
			}
			env := in("echo $API_KEY")
			if !strings.HasPrefix(env, "openshell:resolve:env:") || strings.Contains(env, apiKey) {
				t.Fatalf("API_KEY in the silo is %q, want OpenShell's placeholder", env)
			}
			t.Logf("the silo holds a placeholder: %s…", env[:30])
			want := `"auth": "` + authHash("Bearer "+apiKey) + `"`
			got := in(`/sandbox/hget https://` + apiHost + `/v1/models "Authorization=Bearer $API_KEY"`)
			if !strings.Contains(got, want) {
				t.Errorf("injected key: got %q, want %q", got, want)
			} else {
				t.Log("the placeholder became the key on the way out")
			}
			if got := in(`/sandbox/hget https://` + otherHost + `/`); strings.Contains(got, `"host"`) {
				t.Errorf("a host no grant names answered: %q", got)
			} else {
				t.Logf("a host no grant names: refused (%s)", firstLine(got))
			}
			if got := in(`/sandbox/hget https://` + passHost + `/`); !strings.Contains(got, `"auth": "none"`) {
				t.Errorf("pass (allowed by name, no secret) should answer with nothing injected: %q", got)
			} else {
				t.Log("a name allowed without a secret: reached, nothing injected")
			}
			if n := in(fmt.Sprintf("grep -rl -F -e '%s' /sandbox /tmp 2>/dev/null | wc -l; env | grep -c -F -e '%s'", apiKey, apiKey)); strings.Fields(n)[0] != "0" || strings.Fields(n)[1] != "0" {
				t.Errorf("the key is inside the silo: %q", n)
			}
		})
	}

	// Rotation: once, in Kevaso; both running silos follow with no restart.
	apiKey2 := randomToken(t)
	must(kvo.Run, apiKey2, "secret", "set", "api-key", "-n", "agents", "--from-file", "-")
	for _, s := range []string{"vm", "ct"} {
		ok := false
		for i := 0; i < 40 && !ok; i++ {
			var o bytes.Buffer
			kvo.Run(ctx, []string{"exec", "silo", s, "-n", "agents", "--", "sh", "-c", `/sandbox/hget https://` + apiHost + `/ "Authorization=Bearer $API_KEY"`}, nil, &o, &o)
			ok = strings.Contains(o.String(), authHash("Bearer "+apiKey2))
			if !ok {
				time.Sleep(3 * time.Second)
			}
		}
		if !ok {
			t.Errorf("%s: the rotated key never arrived", s)
		} else {
			t.Logf("%s: rotated key injected", s)
		}
	}

	// On the host: each driver's gateway runs as its own user, locked down; the key isn't in the VM
	// sandbox's disk.
	units, _ := sh("metal", `for u in $(systemctl list-units --plain --no-legend 'kevaso-openshell-*' | awk '{print $1}'); do echo "$u $(systemctl show -p User -p NoNewPrivileges -p ActiveState --value $u | tr '\n' ' ')"; done`)
	t.Logf("gateways:\n%s", units)
	if strings.Count(units, "kevaso-openshell-") != 2 || strings.Contains(units, " root ") || !strings.Contains(units, "yes") {
		t.Errorf("gateways: %q", units)
	}
	if n, _ := sh("metal", fmt.Sprintf("find /var/lib/kevaso-openshell/gw -name overlay.ext4 -exec grep -c -a -F -e '%s' {} + 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}'", apiKey2)); strings.TrimSpace(n) != "0" {
		t.Errorf("the key in a sandbox disk: %q", n)
	}
}
