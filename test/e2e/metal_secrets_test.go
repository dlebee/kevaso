//go:build metal

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/testbed"
)

// metalShell is a container image with curl and a shell that runs as root.
const metalShell = "docker.io/nicolaka/netshoot:v0.13"

// TestMetalSecrets is secrets with no guest helper (ADR 0009), in a microVM and in a container:
// a file and an env delivery written by the host (into a container: the box-deliveries subtest,
// which also rotates the file in place); the local endpoint read with plain curl (and
// refused without its header, and for a secret the grant doesn't name); a key injected by the
// egress gate into an HTTPS request that never appears inside the silo (nor on the VM's disk,
// read from the host); a secret with approval: required that holds the call until it's approved.
//
// Listens on nothing outside (the stand-in API is on the machine's loopback).
func TestMetalSecrets(t *testing.T) {
	c := metal(t)
	ns := "vault"
	c.namespace(ns, "grant/app", "grant/boxapp", "grant/boxfiles", "secret/db-password", "secret/tls-key", "secret/env-token", "secret/api-key", "secret/gh-token", "secret/other")
	dbPassword, tlsValue, envToken := randomValue(t, "pw-"), "-----TLS "+randomValue(t, "")+"-----", randomValue(t, "env-")
	apiKey, ghToken, other := randomValue(t, "sk-"), randomValue(t, "gh-"), randomValue(t, "no-")
	c.must(dbPassword, "create", "secret", "db-password", "-n", ns, "--from-file", "-")
	c.must(tlsValue, "create", "secret", "tls-key", "-n", ns, "--from-file", "-")
	c.must(envToken, "create", "secret", "env-token", "-n", ns, "--from-file", "-")
	c.must(apiKey, "create", "secret", "api-key", "-n", ns, "--from-file", "-", "--allow", "inject", "--write-only")
	c.must(ghToken, "create", "secret", "gh-token", "-n", ns, "--from-file", "-")
	c.must(other, "create", "secret", "other", "-n", ns, "--from-file", "-")
	c.apply(`apiVersion: kevaso/v1
kind: Grant
metadata: { name: app, namespace: ` + ns + ` }
spec:
  secrets:
    - { name: db-password }
    - { name: tls-key, deliver: file, path: /run/secrets/tls.pem }
    - { name: env-token, deliver: env, env: APP_TOKEN }
    - { name: api-key, deliver: inject, to: { host: ` + metalInetName + ` } }
    - { name: gh-token, approval: { required: true } }
---
apiVersion: kevaso/v1
kind: Grant
metadata: { name: boxapp, namespace: ` + ns + ` }
spec:
  secrets:
    - { name: db-password }
    - { name: api-key, deliver: inject, to: { host: ` + metalInetName + ` } }
    - { name: gh-token, approval: { required: true } }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: vm, namespace: ` + ns + ` }
spec:
  runtime: cloud-hypervisor
  vm: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
  grants: [app]
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: box, namespace: ` + ns + ` }
spec:
  runtime: docker
  container: { image: ` + metalShell + `, command: [sh, -c, "while :; do sleep 3600; done"] }
  resources: { cpu: 1, memory: 256Mi }
  grants: [boxapp]
`)
	c.waitRunning(ns, 20*time.Minute, "vm", "box")

	for _, silo := range []string{"vm", "box"} {
		t.Run(silo, func(t *testing.T) {
			c := &mt{metalSuite: c.metalSuite, t: t, ctx: c.ctx}
			in := func(script string) string { o, _ := c.in(ns, silo, script); return o }
			ep := func(path, headers string) string {
				return in("curl -sS --max-time 10 -w ' %{http_code}' " + headers + " 'http://169.254.42.1" + path + "' 2>&1")
			}
			const local = "-H 'Kevaso-Local: 1'"
			c.expect("the endpoint, with plain curl", ep("/v1/secrets/db-password", local), dbPassword+" 200")
			// (A second -H 'Kevaso-Local:' wouldn't take the first one away: curl sends the first.)
			c.expect("without its header: refused", ep("/v1/secrets/db-password", ""), " 403")
			c.expect("from a browser (an Origin): refused", ep("/v1/secrets/db-password", local+" -H 'Origin: http://evil.example'"), " 403")
			c.expect("a secret the grant doesn't name: none", ep("/v1/secrets/other", local), " 404")
			c.expect("an inject-only key: none", ep("/v1/secrets/api-key", local), " 404")
			if silo == "vm" { // a container's file and env deliveries: the box-deliveries subtest
				c.expect("a file the host wrote, in tmpfs", in("cat /run/secrets/tls.pem; echo; stat -c '%a %U' /run/secrets/tls.pem; grep -E ' /run(/secrets)? ' /proc/mounts | awk '{print $3}'"),
					tlsValue+"\n400 root\ntmpfs")
				c.expect("an env delivery the host wrote", in(`set -a; . /run/kevaso/secrets.env; printf '%s' "$APP_TOKEN"`), envToken)
			}

			// The injected key: the stand-in API sees it (as a hash), the silo never does.
			ca := `ca=; [ -f /etc/ssl/certs/kevaso-ca-bundle.crt ] && ca="--cacert /etc/ssl/certs/kevaso-ca-bundle.crt"; `
			got := in(ca + "curl -sS --max-time 15 $ca --resolve " + metalInetName + ":443:203.0.113.9 https://" + metalInetName + "/v1/models 2>&1")
			c.expect("the gate injects the key", got, `"auth": "`+metalHash("Bearer "+apiKey)+`"`)
			half := len(apiKey) / 2
			scan := fmt.Sprintf(`k='%s''%s'; grep -rl -F -e "$k" / --exclude-dir=proc --exclude-dir=sys 2>/dev/null | head -5; `+
				`for e in /proc/[0-9]*/environ; do grep -q -a -F -e "$k" "$e" 2>/dev/null && echo "$e"; done; echo end`, apiKey[:half], apiKey[half:])
			if out := in(scan); out != "end" {
				t.Errorf("the injected key inside the silo:\n%s", out)
			} else {
				t.Log("the injected key inside the silo (files, environments): none")
			}

			// Approval: the call is held until a person says yes.
			ask := `u='http://169.254.42.1/v1/secrets/gh-token?for=5m&wait=3m'; a=
while :; do
  code=$(curl -sS -o /tmp/answer -w '%{http_code}' -H 'Kevaso-Local: 1' "$u${a:+&approval=$a}")
  [ "$code" = 428 ] || break
  a=$(sed -n 's/.*"name":"\([^"]*\)".*/\1/p' /tmp/answer); sleep 2
done
cat /tmp/answer; [ "$code" = 200 ]`
			type result struct {
				out  string
				code int
			}
			done := make(chan result, 1)
			go func() { o, code := c.in(ns, silo, ask); done <- result{o, code} }()
			var pending *v1.Approval
			c.eventually("a pending approval for gh-token", 2*time.Minute, func() (bool, string) {
				out, _ := c.kvo("", "get", "approvals", "-n", ns, "-o", "json")
				for _, raw := range metalItems(out) {
					var a v1.Approval
					if json.Unmarshal(raw, &a) == nil && a.Spec.Silo == silo && a.Spec.Secret == "gh-token" && a.Status.Phase == v1.ApprovalPending {
						pending = &a
						return true, ""
					}
				}
				return false, out
			})
			if pending == nil {
				return
			}
			select {
			case r := <-done:
				t.Fatalf("the call didn't wait for the approval: exit %d %q", r.code, r.out)
			case <-time.After(5 * time.Second):
				t.Log("the call is held while the approval is pending")
			}
			c.must("", "approve", pending.Name, "-n", ns)
			select {
			case r := <-done:
				if r.code != 0 || !strings.Contains(r.out, ghToken) {
					t.Errorf("after the yes: exit %d %q", r.code, r.out)
				} else {
					t.Log("after the yes: the value")
				}
			case <-time.After(time.Minute):
				t.Error("the call never finished after the yes")
			}
		})
	}

	// File and env deliveries into a container (ADR 0009 addendum): the host's tmpfs, a folder of
	// it bind-mounted read-only; env through --env-file, which the engine keeps in the
	// container's config (docker inspect shows it), so admission warns.
	t.Run("box-deliveries", func(t *testing.T) {
		c := &mt{metalSuite: c.metalSuite, t: t, ctx: c.ctx}
		out, code := c.kvo(`apiVersion: kevaso/v1
kind: Grant
metadata: { name: boxfiles, namespace: `+ns+` }
spec:
  secrets:
    - { name: tls-key, deliver: file, path: /run/secrets/tls.pem }
    - { name: env-token, deliver: env, env: APP_TOKEN }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: boxdel, namespace: `+ns+` }
spec:
  runtime: docker
  container: { image: `+metalShell+`, command: [sh, -c, "while :; do sleep 3600; done"] }
  resources: { cpu: 1, memory: 256Mi }
  grants: [boxfiles]
`, "apply", "-f", "-")
		if code != 0 {
			t.Fatalf("file and env deliveries into a docker silo: %s", strings.TrimSpace(out))
		}
		// Docker here takes Kevaso's OCI runtime (envOutsideEngine): nothing to warn about.
		if strings.Contains(out, "Warning:") {
			t.Errorf("admission warned although the host's docker keeps env secrets out of the engine: %s", out)
		}
		c.waitRunning(ns, 10*time.Minute, "boxdel")
		in := func(script string) string { o, _ := c.in(ns, "boxdel", script); return o }
		c.expect("a file the host wrote, in tmpfs", in("cat /run/secrets/tls.pem; echo; stat -c '%a %U' /run/secrets/tls.pem; grep -E ' /run(/secrets)? ' /proc/mounts | awk '{print $3}'"),
			tlsValue+"\n400 root\ntmpfs")
		// Env through kevaso-oci: in the main process's environment, never in the engine's records.
		c.expect("an env delivery, in the container's main process", in(`tr '\0' '\n' < /proc/1/environ | sed -n 's/^APP_TOKEN=//p'`), envToken)
		if got := in(`printf '%s' "${APP_TOKEN:-unset}"`); got != "unset" {
			t.Errorf("kvo exec sees the env secret (the engine built the exec's environment from its config): %q", got)
		}
		uid := c.silo(ns, "boxdel").UID
		main := strings.TrimSpace(c.mustSh("docker ps -q --no-trunc --filter label=kevaso.com/uid=" + uid + " --filter label=kevaso.com/name=boxdel"))
		if main == "" {
			t.Fatal("no main container for boxdel")
		}
		h := len(envToken) / 2
		needle := `k='` + envToken[:h] + `''` + envToken[h:] + `'`
		if out := c.mustSh(needle + `; docker inspect ` + main + ` | grep -c -F -e "$k"; grep -rl -F -e "$k" /var/lib/docker/containers/` + main + ` 2>/dev/null | head -3; true`); strings.TrimSpace(out) != "0" {
			t.Errorf("the env secret is in docker inspect or under /var/lib/docker/containers: %q", out)
		} else {
			t.Log("the env secret is in neither docker inspect nor /var/lib/docker/containers/ID")
		}
		c.expect("boxdel starts through kevaso-oci", c.mustSh("docker inspect -f '{{.HostConfig.Runtime}}' "+main), "kevaso-oci")
		plainUID := c.silo(ns, "box").UID
		c.expect("a silo without env deliveries keeps the default runtime",
			c.mustSh("docker ps -q --filter label=kevaso.com/uid="+plainUID+" --filter label=kevaso.com/name=box | xargs -r docker inspect -f '{{.HostConfig.Runtime}}'"), "runc")
		c.expect("an ordinary container on the host starts with the default runtime",
			c.mustSh("docker run --rm --network none docker.io/library/busybox:1.36 sh -c 'echo plain' 2>&1"), "plain")
		for _, cd := range c.silo(ns, "boxdel").Status.Conditions {
			if cd.Type == "SecretsDelivered" {
				c.expect("SecretsDelivered says which way env went", cd.Message, "Kevaso's OCI runtime")
			}
		}
		if n, _ := strconv.Atoi(strings.TrimSpace(c.mustSh(`since=$(grep -h ' install docker.io' /var/log/dpkg.log | tail -1 | cut -d' ' -f1,2); journalctl -u docker.service --no-pager --since "$since" | grep -c 'Started docker.service' || true`))); n < 1 || n > 2 {
			t.Errorf("docker.service started %d times since it was installed (the package's start, and one restart for its configuration)", n)
		} else {
			t.Logf("docker.service started %d times since it was installed", n)
		}
		c.expect("the file's folder is read-only", in("touch /run/secrets/x 2>&1; echo rc=$?"), "rc=1")
		// Rotation: a file is rewritten in place, no restart.
		rotated := "-----TLS " + randomValue(t, "") + "-----"
		c.must(rotated, "secret", "set", "tls-key", "-n", ns, "--from-file", "-")
		c.eventually("a rotated file reaches the container in place", time.Minute, func() (bool, string) {
			got := in("cat /run/secrets/tls.pem")
			return got == rotated, got
		})
		// Nothing left in the host's tmpfs once the silo is gone.
		c.must("", "delete", "silo", "boxdel", "-n", ns)
		c.eventually("deleted: the host's tmpfs for it is gone", 3*time.Minute, func() (bool, string) {
			out, _ := c.sh("grep -c ' /run/kevaso-secrets/' /proc/mounts; docker ps -aq --filter label=kevaso.com/uid=" + uid)
			return strings.TrimSpace(out) == "0", out
		})
	})

	// The container runtime's own opt-in tests against the real engine (KEVASO_DOCKER_TEST=1):
	// built here for the machine, run there as root.
	t.Run("engine-tests", func(t *testing.T) {
		c := &mt{metalSuite: c.metalSuite, t: t, ctx: c.ctx}
		bin := filepath.Join(t.TempDir(), "container.test")
		build := exec.CommandContext(c.ctx, "go", "test", "-c", "-o", bin, "kevaso.com/core/builtin/kri/container")
		build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+c.arch, "CGO_ENABLED=0")
		if b, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, b)
		}
		if err := c.d.CopyTo(c.ctx, testbed.Machine{}, bin, "/tmp/kvt-container.test"); err != nil {
			t.Fatal(err)
		}
		out, err := c.sh("cd /tmp && KEVASO_DOCKER_TEST=1 /tmp/kvt-container.test -test.run 'OnARealEngine|OnRealDocker' -test.v 2>&1; rc=$?; rm -f /tmp/kvt-container.test; exit $rc")
		t.Logf("the container runtime's real-engine tests on the machine:\n%s", out)
		if err != nil || strings.Contains(out, "--- SKIP") || !strings.Contains(out, "--- PASS") {
			t.Errorf("real-engine tests: %v (a skip counts as a failure here: the machine has the engine)", err)
		}
	})

	// The key never reached the microVM's disk either (read from the host).
	vm := c.silo(ns, "vm")
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: vm.Namespace, Name: vm.Name, UID: vm.UID})
	// The needles are put together on the machine: sudo logs every command line, so no whole
	// secret may be on one.
	needle := func(v string) string { h := len(v) / 2; return "'" + v[:h] + "''" + v[h:] + "'" }
	out, err := c.sh(fmt.Sprintf("sync; k=%s; grep -a -c -F -e \"$k\" /dev/%s/%s || true", needle(apiKey), cloudhypervisor.VG, n.LV))
	if k, _ := strconv.Atoi(strings.TrimSpace(out)); err != nil || k != 0 {
		t.Errorf("the injected key on the vm's disk: %q %v", out, err)
	} else {
		t.Log("the injected key on the vm's disk, from the host: 0 times")
	}
	if leaked, _ := c.sh(fmt.Sprintf(`a=%s; b=%s; g=%s; journalctl --no-pager | grep -c -F -e "$a" -e "$b" -e "$g" || true`,
		needle(apiKey), needle(dbPassword), needle(ghToken))); strings.TrimSpace(leaked) != "0" {
		t.Errorf("a secret is in the machine's journal: %q", leaked)
	} else {
		t.Log("no secret in the machine's journal (kevasod's, sudo's, anyone's)")
	}
}

func metalHash(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])[:16]
}

// metalItems reads kvo get -o json into its items (an array, a list, or one object).
func metalItems(out string) []json.RawMessage {
	data := []byte(strings.TrimSpace(out))
	var items []json.RawMessage
	if json.Unmarshal(data, &items) == nil {
		return items
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
		Kind  string            `json:"kind"`
	}
	if json.Unmarshal(data, &list) != nil {
		return nil
	}
	if list.Items != nil || strings.HasSuffix(list.Kind, "List") {
		return list.Items
	}
	return []json.RawMessage{data}
}
