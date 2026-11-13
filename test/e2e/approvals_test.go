//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/testbed"
)

// TestApprovals is design §8.7 on real machines: a grant makes a secret's use wait for a person's
// yes. On a cloud-hypervisor silo (kvo-guest over vsock) and a docker silo (kvo-guest copied in, the
// broker on the container's own socket): a broker get waits as a pending Approval until
// `kvo approve`, and a second get within the access asked for needs no new yes; `kvo deny` fails the
// call, saying who; an injected key with approval: required holds the HTTPS request at the egress
// gate until approved, and the key itself never reaches the silo.
//
//	metal-1  control plane + worker with KVM (cloud-hypervisor) and docker
//	client   "the internet": HTTPS for api.* (a name from sslip.io)
func TestApprovals(t *testing.T) {
	r := newRig(t, 50*time.Minute, map[string]testbed.Spec{
		"metal":  {Role: "metal", CPUs: 6, Memory: "6GiB", Disk: "40GiB", KVM: true, Shared: true},
		"client": {Role: "client", CPUs: 1, Memory: "1GiB", Disk: "10GiB", Shared: true},
	})
	metalIP, clientIP := r.ip("metal"), r.ip("client")
	apiHost := "api." + strings.ReplaceAll(clientIP, ".", "-") + ".sslip.io"
	t.Logf("metal-1 %s, client %s (%s)", metalIP, clientIP, apiHost)
	ca := r.internet("client", apiHost)
	if _, err := r.sh("metal", fmt.Sprintf("mkdir -p /etc/kevaso && printf '%%s' '%s' > /etc/kevaso/test-internet-ca.pem", ca)); err != nil {
		t.Fatal(err)
	}
	r.must(kvoadm.Run, "", append(append([]string{"init"}, r.sshArgs("metal")...),
		"--name", "metal-1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--address", metalIP, "--worker",
		"--runtime", "cloud-hypervisor", "--runtime", "docker", "--loop-storage", "30G",
		"--egress-extra-ca", "/etc/kevaso/test-internet-ca.pem")...)

	ghToken, deployPw, dbPassword, apiKey := randomToken(t), randomToken(t), randomToken(t), randomToken(t)
	r.must(kvo.Run, "apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: ops }\n", "apply", "-f", "-")
	r.must(kvo.Run, ghToken, "create", "secret", "gh-token", "-n", "ops", "--from-file", "-")
	r.must(kvo.Run, deployPw, "create", "secret", "deploy-pw", "-n", "ops", "--from-file", "-")
	r.must(kvo.Run, dbPassword, "create", "secret", "db-password", "-n", "ops", "--from-file", "-")
	r.must(kvo.Run, apiKey, "create", "secret", "api-key", "-n", "ops", "--from-file", "-", "--allow", "inject", "--write-only")
	r.must(kvo.Run, `apiVersion: kevaso/v1
kind: Grant
metadata: { name: careful, namespace: ops }
spec:
  secrets:
    - { name: gh-token, approval: { required: true } }
    - { name: deploy-pw, approval: { required: true } }
    - { name: db-password }
    - { name: api-key, deliver: inject, to: { host: `+apiHost+` }, approval: { required: true } }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: vm, namespace: ops }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
  grants: [careful]
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: box, namespace: ops }
spec:
  runtime: docker
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 512Mi }
  grants: [careful]
`, "apply", "-f", "-")
	r.waitRunning("ops", 30*time.Minute, "metal", "vm", "box")

	// The docker silo has nothing of Kevaso's: it brings its own broker client (kvo-guest, copied in
	// like any program) and an HTTPS client that waits as long as the gate holds a request.
	guestBin, err := os.ReadFile(r.bin)
	if err != nil {
		t.Fatal(err)
	}
	r.upload("ops", "box", "/usr/local/bin/kvo-guest", guestBin)
	tmp := t.TempDir()
	hget := filepath.Join(tmp, "hget")
	_ = os.WriteFile(filepath.Join(tmp, "hget.go"), []byte(strings.Replace(hgetGo, "15 * time.Second", "4 * time.Minute", 1)), 0o644)
	buildLinux(t, r, hget, filepath.Join(tmp, "hget.go"))
	hgetBin, _ := os.ReadFile(hget)
	r.upload("ops", "box", "/usr/local/bin/hget", hgetBin)

	for _, c := range []struct{ silo, get string }{
		{"vm", "curl -sS --max-time 240 https://" + apiHost + "/v1/models 2>&1"},
		{"box", "hget https://" + apiHost + "/v1/models 2>&1"},
	} {
		t.Run(c.silo, func(t *testing.T) { approvalFlow(t, r.on(t), c.silo, c.get, apiHost, ghToken, deployPw, dbPassword, apiKey) })
	}

	// The key never reached the cloud-hypervisor silo's disk either (read from the host).
	vm := r.silo("ops", "vm")
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: vm.Namespace, Name: vm.Name, UID: vm.UID})
	_, _ = r.sh("metal", "sync")
	out, err := r.sh("metal", fmt.Sprintf("grep -a -c -F -e '%s' /dev/%s/%s || true", apiKey, cloudhypervisor.VG, n.LV))
	if c, _ := strconv.Atoi(strings.TrimSpace(out)); err != nil || c != 0 {
		t.Errorf("the injected key on the vm's disk: %q %v", out, err)
	} else {
		t.Log("the injected key on the vm's disk, from the host: 0 times")
	}
	if leaked, _ := r.sh("metal", fmt.Sprintf("journalctl -u kevasod --no-pager | grep -c -F -e '%s' -e '%s' || true", apiKey, ghToken)); strings.TrimSpace(leaked) != "0" {
		t.Errorf("a secret is in kevasod's journal: %q", leaked)
	}
}

// approvalFlow is the whole flow on one silo.
func approvalFlow(t *testing.T, r *rig, silo, get, apiHost, ghToken, deployPw, dbPassword, apiKey string) {
	type result struct {
		out  string
		code int
	}
	background := func(script string) chan result {
		ch := make(chan result, 1)
		go func() {
			out, code := r.in("ops", silo, script)
			ch <- result{out, code}
		}()
		return ch
	}
	// held: the call is still waiting a few seconds after its approval appeared.
	held := func(what string, ch chan result) {
		t.Helper()
		select {
		case res := <-ch:
			t.Fatalf("%s didn't wait for a yes: exit %d %q", what, res.code, res.out)
		case <-time.After(5 * time.Second):
			t.Logf("%s waits for a yes", what)
		}
	}
	done := func(what string, ch chan result) result {
		t.Helper()
		select {
		case res := <-ch:
			return res
		case <-time.After(90 * time.Second):
			t.Fatalf("%s still waiting after the answer", what)
		}
		return result{}
	}

	// Without approval in the same grant: straight through.
	got, _ := r.in("ops", silo, "kvo-guest secret get db-password")
	expect(t, "a secret without approval", got, dbPassword)

	// 1. A get waits for a yes; kvo approve lets it through.
	ch := background("kvo-guest secret get gh-token --for 5m --wait 3m")
	a := pendingApproval(t, r, silo, "gh-token", v1.ApprovalForSecret)
	if a.Spec.For != "5m0s" || a.Spec.Grant != "careful" {
		t.Errorf("approval %s: %+v", a.Name, a.Spec)
	}
	held("secret get gh-token", ch)
	t.Logf("kvo get approvals:\n%s", r.must(kvo.Run, "", "get", "approvals", "-n", "ops"))
	expect(t, "kvo approve", r.must(kvo.Run, "", "approve", a.Name, "-n", "ops"), "approved until")
	res := done("secret get gh-token", ch)
	if res.code != 0 || !strings.Contains(res.out, ghToken) {
		t.Errorf("after the yes: exit %d %q", res.code, res.out)
	} else {
		t.Logf("after the yes: the value, and it said what it waited on: %s", firstLine(res.out))
	}
	expect(t, "it told the silo what to ask for", res.out, "kvo approve "+a.Name)

	// 2. Within the access asked for: no new yes.
	start := time.Now()
	got, code := r.in("ops", silo, "kvo-guest secret get gh-token --wait 20s")
	if code != 0 || got != ghToken || time.Since(start) > 15*time.Second {
		t.Errorf("a second get within the access: exit %d after %s: %q", code, time.Since(start), got)
	} else {
		t.Logf("a second get within the access: at once (%s), no new approval", time.Since(start).Round(time.Millisecond))
	}
	if n := len(approvalsFor(t, r, silo, "gh-token", v1.ApprovalForSecret, v1.ApprovalPending)); n != 0 {
		t.Errorf("the second get made %d new pending approvals", n)
	}

	// 3. A no fails the call, saying who.
	ch = background("kvo-guest secret get deploy-pw --wait 3m")
	d := pendingApproval(t, r, silo, "deploy-pw", v1.ApprovalForSecret)
	held("secret get deploy-pw", ch)
	expect(t, "kvo deny", r.must(kvo.Run, "", "deny", d.Name, "-n", "ops", "--reason", "not during the freeze"), "denied")
	res = done("secret get deploy-pw", ch)
	who := approvalNamed(t, r, d.Name).Status.AnsweredBy
	if who == "" {
		t.Errorf("the denied approval doesn't say who answered")
	}
	if res.code == 0 || strings.Contains(res.out, deployPw) || !strings.Contains(res.out, "denied by "+who+": not during the freeze") {
		t.Errorf("after the no: exit %d %q (want denied by %s)", res.code, res.out, who)
	} else {
		t.Logf("after the no: %s", firstLine(lastLine(res.out)))
	}

	// 4. An injected key with approval: the gate holds the HTTPS request until the yes.
	ch = background(get)
	in := pendingApproval(t, r, silo, "api-key", v1.ApprovalForInject)
	if in.Spec.Destination == nil || in.Spec.Destination.Host != apiHost || !strings.HasPrefix(in.Spec.Destination.Path, "/v1/models") {
		t.Errorf("inject approval %s: destination %+v", in.Name, in.Spec.Destination)
	}
	held("the HTTPS request at the gate", ch)
	r.must(kvo.Run, "", "approve", in.Name, "-n", "ops")
	res = done("the HTTPS request", ch)
	expect(t, "the held request goes out with the key", res.out, `"auth": "`+authHash("Bearer "+apiKey)+`"`)

	// The key never appears inside the silo: not in its files, not in any process's environment. The
	// needle is put together inside, so the command line itself (which a runtime's exec may keep in
	// an environment variable or a log) never holds it whole.
	half := len(apiKey) / 2
	scan := fmt.Sprintf(`k='%s''%s'; grep -rl -F -e "$k" / --exclude-dir=proc --exclude-dir=sys 2>/dev/null | head -5; `+
		`for e in /proc/[0-9]*/environ; do grep -q -a -F -e "$k" "$e" 2>/dev/null && echo "$e: $(tr '\0' ' ' < "${e%%/environ}/cmdline")"; done; echo end`, apiKey[:half], apiKey[half:])
	if out, _ := r.in("ops", silo, scan); out != "end" {
		t.Errorf("the injected key inside the silo:\n%s", out)
	} else {
		t.Log("the injected key inside the silo (files, environments): none")
	}
}

func lastLine(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return l[len(l)-1]
}

func listApprovals(t *testing.T, r *rig) []*v1.Approval {
	t.Helper()
	out := r.must(kvo.Run, "", "get", "approvals", "-n", "ops", "-o", "json")
	var as []*v1.Approval
	for _, raw := range jsonItems(out) {
		var a v1.Approval
		if json.Unmarshal(raw, &a) == nil {
			as = append(as, &a)
		}
	}
	return as
}

func approvalsFor(t *testing.T, r *rig, silo, secret, use, phase string) []*v1.Approval {
	var out []*v1.Approval
	for _, a := range listApprovals(t, r) {
		if a.Spec.Silo == silo && a.Spec.Secret == secret && a.Spec.Use == use && a.Status.Phase == phase {
			out = append(out, a)
		}
	}
	return out
}

func pendingApproval(t *testing.T, r *rig, silo, secret, use string) *v1.Approval {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if as := approvalsFor(t, r, silo, secret, use, v1.ApprovalPending); len(as) > 0 {
			return as[0]
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("no pending approval for %s's %s of %s:\n%s", silo, use, secret, r.must(kvo.Run, "", "get", "approvals", "-n", "ops"))
	return nil
}

func approvalNamed(t *testing.T, r *rig, name string) *v1.Approval {
	t.Helper()
	var a v1.Approval
	if err := json.Unmarshal([]byte(r.must(kvo.Run, "", "get", "approval", name, "-n", "ops", "-o", "json")), &a); err != nil {
		t.Fatal(err)
	}
	return &a
}

// buildLinux builds a Go program for the machines.
func buildLinux(t *testing.T, r *rig, out, src string) {
	t.Helper()
	b := execGo(r, "build", "-ldflags", "-s -w", "-o", out, src)
	if o, err := b.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", src, err, o)
	}
}
