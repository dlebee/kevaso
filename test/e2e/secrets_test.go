//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/testbed"
)

// inetSetup makes the stand-in internet on the client machine: a CA of its own and one HTTPS
// server for three names, which answers with the Host it got and only a SHA-256 prefix of the
// Authorization header (like E025's echo server: the value itself is never shown).
const inetSetup = `set -e
mkdir -p /etc/inet && cd /etc/inet
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=internet-ca 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout leaf.key -out leaf.csr -subj /CN=api.allowed.test 2>/dev/null
printf 'subjectAltName=DNS:api.allowed.test,DNS:pass.test,DNS:other.blocked.test\n' > ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext -out leaf.pem 2>/dev/null
cat > server.py <<'PY'
import ssl, hashlib, json, http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        a = self.headers.get("Authorization")
        body = json.dumps({"host": self.headers.get("Host"), "auth": hashlib.sha256(a.encode()).hexdigest()[:16] if a else "none"}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/etc/inet/leaf.pem", "/etc/inet/leaf.key")
s = http.server.ThreadingHTTPServer(("0.0.0.0", 443), H); s.socket = ctx.wrap_socket(s.socket, server_side=True); s.serve_forever()
PY
systemd-run --unit=inet python3 /etc/inet/server.py
cat ca.pem
`

func randomToken(t *testing.T) string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "sk-e2e-" + base64.RawURLEncoding.EncodeToString(b)
}

func authHash(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])[:16]
}

// TestSecretsInASilo is M7's "done when": a key works in a silo but never appears inside it. On
// real machines: the egress gate injects an API key for the one host a grant names (and replaces
// what the silo sends, refuses everything else), the host writes file secrets into the silo's
// tmpfs and its local endpoint answers what grants say (ADR 0008),
// signs with a key that stays outside, rotations reach the silo, and then the silo's whole memory
// (a Cloud Hypervisor snapshot) and disk are searched for the key, from the host: zero times.
//
//	metal-1  control plane + KVM worker
//	client   "the internet": HTTPS for api.allowed.test, pass.test, other.blocked.test
func TestSecretsInASilo(t *testing.T) {
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
		"metal":  {Role: "metal", CPUs: 6, Memory: "6GiB", Disk: "40GiB", KVM: true, Shared: true},
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
	t.Logf("metal-1 %s, client %s", metalIP, clientIP)

	// The stand-in internet, and metal-1 told where its names are and to trust its CA upstream.
	caOut, err := sh("client", inetSetup)
	if err != nil {
		t.Fatalf("internet: %v\n%s", err, caOut)
	}
	inetCA := caOut[strings.Index(caOut, "-----BEGIN CERTIFICATE-----"):]
	if _, err := sh("metal", fmt.Sprintf("mkdir -p /etc/kevaso && printf '%%s' '%s' > /etc/kevaso/test-internet-ca.pem && printf '%s api.allowed.test pass.test other.blocked.test\\n' >> /etc/hosts",
		strings.TrimSpace(inetCA), clientIP)); err != nil {
		t.Fatal(err)
	}

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
	info, err := sshd.SSH(ctx, machines["metal"])
	if err != nil {
		t.Fatal(err)
	}
	hk, _ := d.Exec(ctx, machines["metal"], "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub")
	initOut := must(kvoadm.Run, "", "init", info.User+"@"+info.Host, "--ssh-port", strconv.Itoa(info.Port), "--ssh-key", info.KeyFile,
		"--host-key", strings.Fields(hk)[1], "--kevasod", bin, "--name", "metal-1", "--cluster", "e2e",
		"--api-server", "https://127.0.0.1:6443", "--address", metalIP, "--worker", "--loop-storage", "30G",
		"--egress-extra-ca", "/etc/kevaso/test-internet-ca.pem")
	if !strings.Contains(initOut, "Recovery key for secrets") || !strings.Contains(initOut, "KVR1-") {
		t.Fatal("kvoadm init didn't print the recovery key")
	}
	t.Log("kvoadm init printed the recovery key once")

	// Secrets, from stdin: never on a command line.
	apiKey, dbPassword, tlsValue := randomToken(t), randomToken(t), "-----TLS "+randomToken(t)+"-----"
	must(kvo.Run, "apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: dev }\n", "apply", "-f", "-")
	must(kvo.Run, apiKey, "create", "secret", "api-key", "-n", "dev", "--from-file", "-", "--allow", "inject", "--write-only")
	must(kvo.Run, dbPassword, "create", "secret", "db-password", "-n", "dev", "--from-file", "-")
	must(kvo.Run, tlsValue, "create", "secret", "tls-key", "-n", "dev", "--from-file", "-")
	must(kvo.Run, "", "create", "secret", "validator-key", "-n", "dev", "--type", "ed25519", "--generate")
	if _, code := kvoRun(ctx, "", "create", "secret", "x", "-n", "dev", "--from-literal", "oops"); code == 0 {
		t.Fatal("--from-literal without --i-know was accepted")
	}

	manifest := `apiVersion: kevaso/v1
kind: Grant
metadata: { name: api, namespace: dev }
spec:
  secrets:
    - { name: api-key, deliver: inject, to: { host: api.allowed.test } }
  egress:
    - { to: pass.test }
---
apiVersion: kevaso/v1
kind: Grant
metadata: { name: app, namespace: dev }
spec:
  secrets:
    - { name: db-password }
    - { name: tls-key, deliver: file, path: /run/secrets/tls.pem }
  operations:
    sign: { keyRef: validator-key, slashingProtection: true }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: agent, namespace: dev }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
  grants: [api, app]
  init:
    steps:
      - name: marker
        run: echo kevaso-e2e-disk-marker > /root/marker && sync
      - name: secrets-before-init
        run: test -s /run/secrets/tls.pem
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: plain, namespace: dev }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
`
	must(kvo.Run, manifest, "apply", "-f", "-")
	deadline := time.Now().Add(30 * time.Minute)
	waited := 0
	for {
		out, code := kvoRun(ctx, "", "get", "silos", "-n", "dev")
		if code != 0 { // the API restarting, or Lima's port forward dropping: try again
			t.Logf("get silos: %s", strings.TrimSpace(out))
			if time.Now().After(deadline) {
				j, _ := sh("metal", "journalctl -u kevasod -n 120 --no-pager | grep -v 'retry in' | tail -60; systemctl status kevasod --no-pager | head -5")
				t.Fatalf("the API stopped answering:\n%s", j)
			}
			time.Sleep(10 * time.Second)
			continue
		}
		if strings.Count(out, "Running") == 2 {
			t.Logf("silos:\n%s", out)
			break
		}
		if waited++; waited%12 == 0 {
			t.Logf("still waiting:\n%s", out)
		}
		if time.Now().After(deadline) || strings.Contains(out, "Failed") {
			j, _ := sh("metal", "journalctl -u kevasod -n 80 --no-pager")
			desc, _ := kvoRun(ctx, "", "describe", "silo", "agent", "-n", "dev")
			t.Fatalf("silos:\n%s\n%s\nkevasod:\n%s", out, desc, j)
		}
		time.Sleep(10 * time.Second)
	}
	t.Logf("describe grant api:\n%s", must(kvo.Run, "", "describe", "grant", "api", "-n", "dev"))

	in := func(silo, script string) string {
		var o bytes.Buffer
		kvo.Run(ctx, []string{"exec", "silo", silo, "-n", "dev", "--", "sh", "-c", script}, nil, &o, &o)
		return strings.TrimSpace(o.String())
	}
	curl := func(silo, name, resolveTo, extra string) string {
		return in(silo, fmt.Sprintf("curl -sS --max-time 8 %s --resolve %s:443:%s https://%s/v1/models 2>&1", extra, name, resolveTo, name))
	}
	expect := func(what, got, want string) {
		t.Helper()
		if !strings.Contains(got, want) {
			t.Errorf("%s: got %q, want %q", what, got, want)
		} else {
			t.Logf("%s: ok", what)
		}
	}
	fails := func(what, got string) {
		t.Helper()
		if strings.Contains(got, `"host"`) {
			t.Errorf("%s should fail, got %q", what, got)
		} else {
			t.Logf("%s: refused (%s)", what, firstLine(got))
		}
	}

	// Tier 2: injection at the gate. The silo resolves the name anywhere; the gate goes to the real one.
	expect("injected key reaches api.allowed.test", curl("agent", "api.allowed.test", "203.0.113.9", ""), `"auth": "`+authHash("Bearer "+apiKey)+`"`)
	expect("the silo's own Authorization is replaced", curl("agent", "api.allowed.test", "203.0.113.9", "-H 'Authorization: Bearer fake'"), `"auth": "`+authHash("Bearer "+apiKey)+`"`)
	fails("a host no grant names", curl("agent", "other.blocked.test", clientIP, ""))
	fails("…even with -k", curl("agent", "other.blocked.test", clientIP, "-k"))
	fails("no SNI (by address)", in("agent", "curl -sSk --max-time 8 https://"+clientIP+"/ 2>&1"))
	fails("domain fronting", curl("agent", "api.allowed.test", "203.0.113.9", "-H 'Host: other.blocked.test'"))
	pass := curl("agent", "pass.test", clientIP, "-kv")
	expect("a name allowed without a secret passes through (the real certificate)", pass, "CN=internet-ca")
	expect("…with nothing injected", pass, `"auth": "none"`)
	fails("plain HTTP (default deny)", in("agent", "curl -sS --max-time 5 http://"+clientIP+"/ 2>&1"))
	fails("a silo without grants", curl("plain", "api.allowed.test", "203.0.113.9", ""))

	// Tiers 3 and 4: the local endpoint (curl, nothing of Kevaso's in the silo) and a file the host wrote.
	// ep prints the body, then the status.
	ep := func(silo, path, extra string) string {
		return in(silo, "curl -sS --max-time 10 -w ' %{http_code}' -H 'Kevaso-Local: 1' "+extra+" 'http://169.254.42.1"+path+"' 2>&1")
	}
	expect("broker: db-password", ep("agent", "/v1/secrets/db-password", ""), dbPassword+" 200")
	expect("file delivery in tmpfs", in("agent", "cat /run/secrets/tls.pem; echo; stat -c '%a %U' /run/secrets/tls.pem; df --output=fstype /run/secrets | tail -1"), tlsValue+"\n400 root\ntmpfs")
	expect("broker: an inject-only key", ep("agent", "/v1/secrets/api-key", ""), "no secret")
	expect("broker: the signing key itself", ep("agent", "/v1/secrets/validator-key", ""), "no secret")
	expect("broker: a file secret isn't the endpoint's", ep("agent", "/v1/secrets/tls-key", ""), " 404")
	expect("broker: no header, nothing", ep("agent", "/v1/secrets/db-password", "-H 'Kevaso-Local:'"), " 403")
	expect("broker: a browser's request, nothing", ep("agent", "/v1/secrets/db-password", "-H 'Origin: http://evil.example'"), " 403")
	if got := ep("plain", "/v1/secrets/db-password", ""); strings.Contains(got, dbPassword) || strings.Contains(got, " 200") {
		t.Errorf("a silo whose grants need no endpoint reached it: %q", got)
	} else {
		t.Logf("a silo whose grants need no endpoint has none: %s", firstLine(got))
	}
	var key v1.Secret
	if err := json.Unmarshal([]byte(must(kvo.Run, "", "get", "secret", "validator-key", "-n", "dev", "-o", "json")), &key); err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(key.Status.PublicKey)
	sigHex := in("agent", "printf 'block 1' | curl -fsS -H 'Kevaso-Local: 1' --data-binary @- 'http://169.254.42.1/v1/sign/validator-key?slot=1'")
	sig, _ := hex.DecodeString(sigHex)
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte("block 1"), sig) {
		t.Errorf("Sign: %q doesn't verify with the key's public half", sigHex)
	} else {
		t.Log("Sign through the local endpoint verifies with the public key")
	}
	expect("slashing protection", in("agent", "printf 'block 1, other' | curl -sS -w ' %{http_code}' -H 'Kevaso-Local: 1' --data-binary @- 'http://169.254.42.1/v1/sign/validator-key?slot=1'"), "slashing")

	// Rotation: one place, the silo follows (gate at once, the file within seconds).
	apiKey2, tls2 := randomToken(t), "-----TLS "+randomToken(t)+"-----"
	must(kvo.Run, apiKey2, "secret", "set", "api-key", "-n", "dev", "--from-file", "-")
	must(kvo.Run, tls2, "secret", "set", "tls-key", "-n", "dev", "--from-file", "-")
	waitFor := func(what string, f func() bool) {
		t.Helper()
		for i := 0; i < 30; i++ {
			if f() {
				t.Logf("%s: ok after %ds", what, i)
				return
			}
			time.Sleep(time.Second)
		}
		t.Errorf("%s: never happened", what)
	}
	waitFor("rotated key injected", func() bool {
		return strings.Contains(curl("agent", "api.allowed.test", "203.0.113.9", ""), authHash("Bearer "+apiKey2))
	})
	waitFor("rotated file rewritten", func() bool { return in("agent", "cat /run/secrets/tls.pem") == tls2 })

	// Never inside: the silo's whole memory and disk, from the host.
	var s v1.Silo
	if err := json.Unmarshal([]byte(must(kvo.Run, "", "get", "silo", "agent", "-n", "dev", "-o", "json")), &s); err != nil {
		t.Fatal(err)
	}
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID})
	chr := cloudhypervisor.BinDir + "/ch-remote --api-socket " + n.Socket
	snap := n.Dir + "/snap"
	if out, err := sh("metal", fmt.Sprintf("rm -rf %[1]s && install -d -o %[2]s -g %[2]s %[1]s && %[3]s pause && %[3]s snapshot file://%[1]s; %[3]s resume; ls -la %[1]s", snap, cloudhypervisor.VMMUser, chr)); err != nil || !strings.Contains(out, "memory-ranges") {
		t.Fatalf("snapshot: %v\n%s", err, out)
	}
	count := func(file, needle string) int {
		out, err := sh("metal", fmt.Sprintf("grep -a -o -F -e '%s' %s | wc -l", needle, file))
		if err != nil {
			t.Fatalf("scan %s: %v %s", file, err, out)
		}
		c, _ := strconv.Atoi(strings.TrimSpace(out))
		return c
	}
	mem, disk := snap+"/memory-ranges", "/dev/"+cloudhypervisor.VG+"/"+n.LV
	for _, c := range []struct {
		where, file, needle string
		want0               bool
	}{
		{"memory", mem, apiKey, true},
		{"memory", mem, apiKey2, true},
		{"memory", mem, tls2, false}, // control: the file delivery is in its RAM (tmpfs)
		{"disk", disk, apiKey, true},
		{"disk", disk, apiKey2, true},
		{"disk", disk, tls2, true},                      // tmpfs: a file delivery never reaches the disk
		{"disk", disk, "kevaso-e2e-disk-marker", false}, // control: the scan reads the disk
	} {
		got := count(c.file, c.needle)
		what := "the API key"
		switch c.needle {
		case tls2:
			what = "the delivered file's value"
		case "kevaso-e2e-disk-marker":
			what = "the disk marker"
		case apiKey2:
			what = "the rotated API key"
		}
		if c.want0 && got != 0 {
			t.Errorf("%s found %d times in the silo's %s", what, got, c.where)
		} else if !c.want0 && got == 0 {
			t.Errorf("control: %s not found in the silo's %s: the scan doesn't work", what, c.where)
		} else {
			t.Logf("%s in the silo's %s: %d", what, c.where, got)
		}
	}
	_, _ = sh("metal", "rm -rf "+snap)

	// The master key rotates under the secrets; every call above is in the audit log.
	rot, err := sh("metal", "kevasod admin kms-rotate")
	if err != nil || !strings.Contains(rot, `"rewrapped":4`) {
		t.Errorf("kms-rotate: %v %s", err, rot)
	}
	expect("after the master key rotation", must(kvo.Run, "", "get", "secret", "db-password", "-n", "dev", "--reveal"), dbPassword)
	if out, _ := kvoRun(ctx, "", "get", "secret", "api-key", "-n", "dev", "--reveal"); !strings.Contains(out, "write-only") {
		t.Errorf("revealing a write-only secret: %q", out)
	}
	audit, _ := sh("metal", `grep -c '"event":"broker"' /var/lib/kevaso/audit.log; grep '"event":"broker"' /var/lib/kevaso/audit.log | grep -c '"allowed":false'`)
	t.Logf("broker calls in the audit log (all, refused): %s", strings.Join(strings.Fields(audit), ", "))
	if f := strings.Fields(audit); len(f) != 2 || f[0] == "0" || f[1] == "0" {
		t.Errorf("audit log: %q", audit)
	}
	if leaked, _ := sh("metal", fmt.Sprintf("grep -c -F -e '%s' /var/lib/kevaso/audit.log; journalctl -u kevasod --no-pager | grep -c -F -e '%s'", apiKey, apiKey)); strings.Fields(leaked)[0] != "0" || strings.Fields(leaked)[1] != "0" {
		t.Errorf("the API key is in the audit log or kevasod's journal: %q", leaked)
	}
}

// kvoRun runs kvo and returns its combined output and exit code.
func kvoRun(ctx context.Context, stdin string, args ...string) (string, int) {
	var o bytes.Buffer
	code := kvo.Run(ctx, args, strings.NewReader(stdin), &o, &o)
	return o.String(), code
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}
