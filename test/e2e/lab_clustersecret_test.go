//go:build metal

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/operators"
	"kevaso.com/core/internal/sshboot"
	"kevaso.com/core/testbed/remote"
)

// Names this test creates. All of them start with kvt so a lab host (which this
// test does not log into) is never asked to touch anything else.
const (
	labSecret     = "kvt-cs-token"
	labCtrlSecret = "kvt-cs-ctrl"
	labPlugin     = "kvtcs"
	labNS         = "kvtcs"
	labUser       = "kvtada"
	labUnit       = "kevaso-plugin-kvtcs-node.service"
	labRole       = "kvtcs"
	labCtrlRole   = "kvtcs-ctrl"
)

// TestLabClusterSecret is ClusterSecret delivery on a worktree lab (testbed/lab):
// one system node and worker w1, already installed by lab-up. It does not call
// metal(), so the metal suite's reset does not run against the lab.
//
// Source testbed/lab/.labs/NAME/env.sh first. Without LAB_NAME the test skips,
// which keeps it out of a bare-metal run.
func TestLabClusterSecret(t *testing.T) {
	if os.Getenv("LAB_NAME") == "" {
		t.Skip("LAB_NAME is unset: source testbed/lab/.labs/NAME/env.sh (this test runs against a worktree lab)")
	}
	cfgPath := os.Getenv("KVO_CONFIG")
	keyFile := os.Getenv("KEVASO_METAL_KEY")
	if cfgPath == "" || keyFile == "" {
		t.Fatal("KVO_CONFIG and KEVASO_METAL_KEY come from the lab env file")
	}
	labDir := filepath.Dir(cfgPath)
	if _, err := os.Stat(filepath.Join(labDir, ".kevaso", "signing.key")); err != nil {
		t.Fatalf("lab signing key: %v", err)
	}
	kcfg, err := kvoconfig.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	admin := kcfg.CurrentContext
	if admin == "" {
		t.Fatal("the lab config has no current context")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	t.Cleanup(cancel)

	sys := labGetHost(t, ctx, admin, "sys")
	w1h := labGetHost(t, ctx, admin, "w1")
	node := labDial(t, ctx, w1h, keyFile)
	var installed bool
	t.Cleanup(func() { labFinish(ctx, t, node, labDir, admin, installed) })

	arch := labArch(t, node)
	bin, manifest := labBuildPlugin(t, arch)
	aVal := randomValue(t, "kvtcs-a-")
	bVal := randomValue(t, "kvtcs-b-")
	aFile, bFile := labValueFiles(t, aVal, bVal)
	aHash, bHash := labHash(aVal), labHash(bVal)

	// 1. The secret, a ClusterRole pinned to that one name, and a binding to the
	// plugin's service account. Install creates the account; the binding may
	// name it first.
	out := labKvo(t, ctx, "", "create", "--context", admin, "clustersecret", labSecret,
		"--description", "lab clustersecret test", "--from-file", aFile)
	t.Logf("create: %s", labRedact(strings.TrimSpace(out), aVal, bVal))
	if !strings.Contains(out, "version 1") {
		t.Fatalf("create: want version 1: %s", labRedact(out, aVal, bVal))
	}
	labKvo(t, ctx, labRoleYAML(), "apply", "--context", admin, "-f", "-")
	t.Logf("step 1: clustersecret %s version 1, ClusterRole %s pinned to it, bound to %s/%s and %s/%s",
		labSecret, labRole, v1.PluginNamespace, operators.ServiceAccountName(labPlugin),
		v1.PluginNamespace, operators.ServiceAccountNodeName(labPlugin))

	// 2. Install the node side on w1. The unit is enabled and not started: kevasod
	// writes the credential and starts it (pluginInstall, secret path).
	out = labKvoadm(t, ctx, labDir, "plugin", "install", w1h.user+"@"+w1h.addr,
		"--ssh-port", strconv.Itoa(w1h.port), "--ssh-key", keyFile, "--host-key", w1h.hostKey,
		"--name", labPlugin, "--binary", bin, "--side", "node", "--manifest", manifest,
		"--cluster-secret", labSecret)
	installed = true
	t.Logf("plugin install:\n%s", labRedact(out, aVal, bVal))
	if !strings.Contains(out, "cluster secrets "+labSecret+" recorded") {
		t.Fatalf("install did not record %s", labSecret)
	}
	cred := labCredentialPath(t, node)
	t.Logf("step 2: unit %s loads %s", labUnit, cred)

	// 3. The file kevasod writes: mode 0600, owner root, bytes equal to the value
	// (compared by sha256; the value is not logged).
	got := labAwaitFile(t, node, cred, aHash, 60*time.Second, aVal, bVal)
	if got.mode != "600" || got.owner != "root" {
		node.fatal(t, "credential file", fmt.Sprintf("mode %s owner %s, want 600 root", got.mode, got.owner), aVal, bVal)
	}
	u0 := labAwaitStable(t, node, aVal, bVal)
	t.Logf("step 3: sha256 %s mode %s owner %s pid %s started %s", got.hash, got.mode, got.owner, u0.pid, u0.started)

	// A secret bound only to the controller account is refused to the worker, and a
	// secret bound to both accounts is readable by the worker and by the system node.
	ctrlVal := randomValue(t, "kvtcs-ctrl-")
	ctrlFile, _ := labValueFiles(t, ctrlVal, ctrlVal)
	out = labKvo(t, ctx, "", "create", "--context", admin, "clustersecret", labCtrlSecret, "--from-file", ctrlFile)
	t.Logf("controller-only secret: %s", labRedact(strings.TrimSpace(out), aVal, bVal, ctrlVal))
	labKvo(t, ctx, labCtrlRoleYAML(), "apply", "--context", admin, "-f", "-")
	apiIP := labAPIAddrs(t, node, sys.internal)[0]
	for _, side := range []string{"node", "controller"} {
		code, _, msg := labFetch(t, node, apiIP, labCtrlSecret, side, aVal, bVal, ctrlVal)
		if code != 403 || !strings.Contains(msg, "side") {
			node.fatal(t, "worker fetch of a controller-only secret", fmt.Sprintf("side=%s http %d, want 403 naming the side: %s", side, code, msg), aVal, bVal, ctrlVal)
		}
	}
	// The worker reads the shared secret, bound to both accounts, for its node side.
	code, hash, _ := labFetch(t, node, apiIP, labSecret, "node", aVal, bVal, ctrlVal)
	if code != 200 || hash != aHash {
		node.fatal(t, "worker, a secret bound to both accounts", fmt.Sprintf("http %d sha256 %s", code, hash), aVal, bVal, ctrlVal)
	}
	// The system node has no certificate file: its controller side is delivered in-process as
	// host/control-plane, which the integration tests cover for both sides.
	t.Logf("step 3 sides: worker refused the controller-only secret; it reads the secret bound to both accounts")

	// 4. A new value rewrites the file and restarts the unit once, within 60s.
	// The same bytes again leave the file and the unit alone.
	out = labKvo(t, ctx, "", "set", "--context", admin, "clustersecret", labSecret, "--from-file", bFile)
	t.Logf("set: %s", labRedact(strings.TrimSpace(out), aVal, bVal))
	rot := labAwaitRotation(t, node, cred, bHash, got.inode, u0, 60*time.Second, aVal, bVal)
	t.Logf("step 4 rotate: sha256 %s inode %s -> %s pid %s -> %s started %s",
		rot.file.hash, got.inode, rot.file.inode, u0.pid, rot.unit.pid, rot.unit.started)
	out = labKvo(t, ctx, "", "set", "--context", admin, "clustersecret", labSecret, "--from-file", bFile)
	t.Logf("set same bytes: %s", labRedact(strings.TrimSpace(out), aVal, bVal))
	if err := node.holds(60*time.Second, cred, rot.file, rot.unit); err != nil {
		node.fatal(t, "same bytes", err.Error(), aVal, bVal)
	}
	t.Logf("step 4 same bytes: sha256 %s inode %s pid %s unchanged for 60s", rot.file.hash, rot.file.inode, rot.unit.pid)

	// 5. Cut w1 off from the system node, then take the binding away. Held or cut
	// off, the cache stays. Back in contact, a 403 removes the file and restarts.
	ips := labAPIAddrs(t, node, sys.internal)
	t.Logf("cutting w1 off from %s", strings.Join(ips, ", "))
	node.must("nft delete table inet kvt-cut 2>/dev/null || true\n" + labCutScript(ips))
	for _, ip := range ips {
		if st := node.tcp(ip); st != "CLOSED" {
			node.fatal(t, "cut", ip+" is "+st+" after the nft drop", aVal, bVal)
		}
	}
	labKvo(t, ctx, "", "delete", "--context", admin, "clusterrolebinding", labRole)
	if err := node.holds(60*time.Second, cred, rot.file, rot.unit); err != nil {
		node.fatal(t, "cut off", err.Error(), aVal, bVal)
	}
	t.Logf("step 5 cut: file sha256 %s still there after 60s, pid %s", rot.file.hash, rot.unit.pid)
	node.must("nft delete table inet kvt-cut")
	gone := labAwaitRemoval(t, node, cred, rot.unit, ips, 2*time.Minute, aVal, bVal)
	t.Logf("step 5 uncut: file removed, unit %s pid %s started %s (%s)", gone.state, gone.pid, gone.started, gone.result)

	// The binding is put back, the file returns, and deleting the ClusterSecret
	// itself removes the file within a minute. The secret is created again so the
	// namespace-admin check below still meets a secret it must not read.
	labKvo(t, ctx, labRoleYAML(), "apply", "--context", admin, "-f", "-")
	back := labAwaitFile(t, node, cred, bHash, time.Minute, aVal, bVal)
	backUnit := labAwaitStable(t, node, aVal, bVal)
	labKvo(t, ctx, "", "delete", "--context", admin, "clustersecret", labSecret)
	deleted := labAwaitRemoval(t, node, cred, backUnit, nil, time.Minute, aVal, bVal)
	t.Logf("step 5 delete: file removed within a minute, unit %s (was inode %s)", deleted.state, back.inode)
	out = labKvo(t, ctx, "", "create", "--context", admin, "clustersecret", labSecret, "--from-file", bFile)
	t.Logf("secret recreated: %s", labRedact(strings.TrimSpace(out), aVal, bVal))

	// 6. A namespace admin (invite into a namespace as admin, the same binding
	// kvoadm users invite writes) cannot read the value, cannot bind anyone into
	// kevaso-system, and cannot mint a token for the plugin account.
	labNamespaceAdmin(t, ctx, admin, aVal, bVal)
	t.Logf("step 6: namespace admin refused the value, a RoleBinding in %s, and a token for %s",
		v1.PluginNamespace, operators.ServiceAccountName(labPlugin))
}

// labFinish removes what the test created. The lab is thrown away by lab-down;
// this still drops the cut and the plugin so a failure mid-test leaves w1 usable.
func labFinish(ctx context.Context, t *testing.T, node *labNode, labDir, admin string, installed bool) {
	t.Helper()
	if node != nil {
		_, _ = node.sh("nft delete table inet kvt-cut 2>/dev/null || true")
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	_, _ = labKvoCode(cctx, "", "ctx", admin)
	if installed && node != nil {
		out, code := labKvoadmCode(cctx, labDir, "plugin", "remove", node.user+"@"+node.addr,
			"--ssh-port", strconv.Itoa(node.port), "--ssh-key", node.keyFile, "--host-key", node.hostKey,
			"--name", labPlugin, "--side", "node")
		if code != 0 {
			t.Logf("cleanup plugin remove: exit %d %s", code, strings.TrimSpace(labRedact(out)))
		}
	}
	for _, args := range [][]string{
		{"delete", "--context", admin, "rolebinding", labUser + "-admin", "-n", labNS},
		{"delete", "--context", admin, "namespace", labNS},
		{"delete", "--context", admin, "clusterrolebinding", labRole},
		{"delete", "--context", admin, "clusterrole", labRole},
		{"delete", "--context", admin, "clusterrolebinding", labCtrlRole},
		{"delete", "--context", admin, "clusterrole", labCtrlRole},
		{"delete", "--context", admin, "clustersecret", labSecret},
		{"delete", "--context", admin, "clustersecret", labCtrlSecret},
	} {
		out, code := labKvoCode(cctx, "", args...)
		if code != 0 && !strings.Contains(out, "NotFound") {
			t.Logf("cleanup %v: %s", args, strings.TrimSpace(out))
		}
	}
	if node != nil {
		_ = node.d.Close()
	}
}

func labRoleYAML() string {
	ctrl := operators.ServiceAccountName(labPlugin)
	node := operators.ServiceAccountNodeName(labPlugin)
	return fmt.Sprintf(`apiVersion: kevaso/v1
kind: ClusterRole
metadata: { name: %s }
rules:
  - verbs: [get]
    resources: [clustersecrets/value]
    resourceNames: [%s]
---
apiVersion: kevaso/v1
kind: ClusterRoleBinding
metadata: { name: %s }
roleRef: { kind: ClusterRole, name: %s }
subjects:
  - { kind: ServiceAccount, name: %s, namespace: %s }
  - { kind: ServiceAccount, name: %s, namespace: %s }
`, labRole, labSecret, labRole, labRole, ctrl, v1.PluginNamespace, node, v1.PluginNamespace)
}

// labCtrlRoleYAML binds the controller account only. The node account is not a subject.
func labCtrlRoleYAML() string {
	ctrl := operators.ServiceAccountName(labPlugin)
	return fmt.Sprintf(`apiVersion: kevaso/v1
kind: ClusterRole
metadata: { name: %s }
rules:
  - verbs: [get]
    resources: [clustersecrets/value]
    resourceNames: [%s]
---
apiVersion: kevaso/v1
kind: ClusterRoleBinding
metadata: { name: %s }
roleRef: { kind: ClusterRole, name: %s }
subjects:
  - { kind: ServiceAccount, name: %s, namespace: %s }
`, labCtrlRole, labCtrlSecret, labCtrlRole, labCtrlRole, ctrl, v1.PluginNamespace)
}

// labFetch reads one value with the host certificate and returns the HTTP status, the
// sha256 of the body, and the body when the status is not 200. The body file is removed
// on the host. A 200 body is not returned.
func labFetch(t *testing.T, n *labNode, ip, name, side string, secrets ...string) (int, string, string) {
	t.Helper()
	q := sshboot.Quote("https://" + ip + ":6443/apis/kevaso/v1/clustersecrets/" + name + "/value?for=" + labPlugin + "&side=" + side)
	out := n.must("body=$(mktemp); code=$(curl -sS -o \"$body\" -w '%{http_code}' --cacert /etc/kevaso/ca.crt --cert /var/lib/kevaso/pki/host.crt --key /var/lib/kevaso/pki/host.key " + q + "); hash=$(sha256sum \"$body\" | awk '{print $1}'); msg=; if [ \"$code\" != 200 ]; then msg=$(tr '\\n' ' ' < \"$body\"); fi; rm -f \"$body\"; printf '%s %s\\n%s\\n' \"$code\" \"$hash\" \"$msg\"")
	lines := strings.SplitN(strings.TrimRight(out, "\n"), "\n", 2)
	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		n.fatal(t, "fetch", out, secrets...)
	}
	code, err := strconv.Atoi(fields[0])
	if err != nil {
		n.fatal(t, "fetch", out, secrets...)
	}
	msg := ""
	if len(lines) == 2 {
		msg = strings.TrimSpace(lines[1])
	}
	return code, fields[1], msg
}

func labNamespaceAdmin(t *testing.T, ctx context.Context, admin, aVal, bVal string) {
	t.Helper()
	labKvo(t, ctx, "apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: "+labNS+" }\n",
		"apply", "--context", admin, "-f", "-")
	inv := labKvoadm(t, ctx, filepath.Dir(os.Getenv("KVO_CONFIG")), "users", "invite", labUser, "--namespace", labNS, "--role", "admin")
	t.Logf("invite: %s", labRedact(inv, aVal, bVal))
	loginMatch := regexp.MustCompile(`kvo login (\S+) --ca (sha256:[0-9a-f]{64})`).FindStringSubmatch(inv)
	inviteMatch := regexp.MustCompile(`invite code: (kvi_\S+)`).FindStringSubmatch(inv)
	if loginMatch == nil || inviteMatch == nil {
		t.Fatalf("invite output had no login line after redaction: %s", labRedact(inv, aVal, bVal))
	}
	if !strings.Contains(inv, labUser+" is admin in namespace "+labNS) {
		t.Fatalf("invite did not bind %s as admin in %s", labUser, labNS)
	}
	saved := kvo.Browser
	kvo.Browser = func(authURL string) error { return labPlayBrowser(authURL, inviteMatch[1]) }
	defer func() { kvo.Browser = saved }()
	out := labKvo(t, ctx, "", "login", loginMatch[1], "--ca", loginMatch[2], "--context", labUser)
	out = strings.ReplaceAll(out, inviteMatch[1], "[invite]")
	t.Logf("login: %s", labRedact(strings.TrimSpace(out), aVal, bVal))
	who := labKvo(t, ctx, "", "auth", "--context", labUser, "whoami")
	if !strings.Contains(who, "user "+labUser) {
		t.Fatalf("whoami: %s", labRedact(who, aVal, bVal))
	}
	// The binding is real: this user can work in the namespace they administer.
	if out, code := labKvoCode(ctx, "", "auth", "--context", labUser, "can-i", "get", "silo", "-n", labNS); code != 0 {
		t.Fatalf("admin of %s cannot get a silo there: %s", labNS, labRedact(out, aVal, bVal))
	}

	reveal, code := labKvoCode(ctx, "", "get", "--context", labUser, "clustersecret", labSecret, "--reveal")
	if code == 0 || strings.Contains(reveal, aVal) || strings.Contains(reveal, bVal) {
		sum := sha256.Sum256([]byte(reveal))
		t.Fatalf("namespace admin read the value: exit %d sha256 %s", code, hex.EncodeToString(sum[:]))
	}
	if !strings.Contains(reveal, "Forbidden") {
		t.Fatalf("reveal: want Forbidden, got %s", labRedact(reveal, aVal, bVal))
	}
	t.Logf("reveal: %s", oneLine(labRedact(reveal, aVal, bVal)))

	bind := fmt.Sprintf(`apiVersion: kevaso/v1
kind: RoleBinding
metadata: { name: kvt-try, namespace: %s }
roleRef: { kind: ClusterRole, name: admin }
subjects: [{ kind: User, name: %s }]
`, v1.PluginNamespace, labUser)
	got, code := labKvoCode(ctx, bind, "apply", "--context", labUser, "-f", "-")
	if code == 0 {
		t.Fatalf("namespace admin created a RoleBinding in %s", v1.PluginNamespace)
	}
	if !strings.Contains(got, "Forbidden") {
		t.Fatalf("RoleBinding in %s: want Forbidden, got %s", v1.PluginNamespace, labRedact(got, aVal, bVal))
	}
	t.Logf("rolebinding: %s", oneLine(labRedact(got, aVal, bVal)))

	tok, code := labKvoCode(ctx, "", "create", "--context", labUser, "token", operators.ServiceAccountName(labPlugin), "-n", v1.PluginNamespace)
	if code == 0 {
		t.Fatalf("namespace admin minted a token: %d bytes of output", len(tok))
	}
	if strings.Contains(tok, aVal) || strings.Contains(tok, bVal) || !strings.Contains(tok, "Forbidden") {
		t.Fatalf("token: want Forbidden, got %s", labRedact(tok, aVal, bVal))
	}
	t.Logf("token: %s", oneLine(labRedact(tok, aVal, bVal)))
}

// labPlayBrowser does what a person does on the sign-in page. The invite code is
// posted and not logged.
func labPlayBrowser(authURL, code string) error {
	resp, err := http.Get(authURL)
	if err != nil {
		return err
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(page), "Sign in to Kevaso") {
		return errors.New("no sign-in page")
	}
	u, _ := url.Parse(authURL)
	form := url.Values{"invite": {code}}
	for _, k := range []string{"redirect_uri", "state", "code_challenge", "nonce"} {
		form.Set(k, u.Query().Get(k))
	}
	resp, err = http.PostForm("http://"+u.Host+client.PathLogin, form)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// --- lab worker ---------------------------------------------------------------

type labHost struct {
	user, addr, hostKey, internal string
	port                          int
}

type labNode struct {
	t        *testing.T
	d        *remote.Driver
	ctx      context.Context
	user     string
	addr     string
	hostKey  string
	keyFile  string
	port     int
	ownAddrs map[string]bool
}

func labGetHost(t *testing.T, ctx context.Context, admin, name string) labHost {
	t.Helper()
	out := labKvo(t, ctx, "", "get", "--context", admin, "host", name, "-o", "json")
	var h v1.Host
	if err := json.Unmarshal([]byte(jsonObject(out)), &h); err != nil {
		t.Fatalf("host %s: %v\n%s", name, err, out)
	}
	user, hostport, ok := strings.Cut(h.Annotations[kvoadm.AnnotationSSH], "@")
	if !ok {
		t.Fatalf("host %s has no %s annotation", name, kvoadm.AnnotationSSH)
	}
	addr, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("host %s ssh %q: %v", name, h.Annotations[kvoadm.AnnotationSSH], err)
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		t.Fatal(err)
	}
	pin := h.Annotations[kvoadm.AnnotationSSHHostKey]
	if !strings.HasPrefix(pin, "SHA256:") {
		t.Fatalf("host %s: ssh host key %q", name, pin)
	}
	return labHost{user: user, addr: addr, port: port, hostKey: pin, internal: h.Spec.InternalIP}
}

func labDial(t *testing.T, ctx context.Context, h labHost, keyFile string) *labNode {
	t.Helper()
	n := &labNode{t: t, ctx: ctx, d: remote.New(remote.Config{
		User: h.user, Address: h.addr, Port: h.port, KeyFile: keyFile, HostKey: h.hostKey,
	}), user: h.user, addr: h.addr, port: h.port, hostKey: h.hostKey, keyFile: keyFile}
	n.ownAddrs = map[string]bool{}
	for _, ip := range strings.Fields(n.must("hostname -I")) {
		n.ownAddrs[ip] = true
	}
	t.Logf("w1 %s via %s:%d (%s)", strings.TrimSpace(n.must("hostname")), h.addr, h.port, h.hostKey)
	return n
}

func (n *labNode) sh(script string) (string, error) {
	out, err := n.d.Run(n.ctx, script, nil)
	var exit *ssh.ExitError
	if err != nil && !errors.As(err, &exit) {
		out, err = n.d.Run(n.ctx, script, nil)
	}
	return out, err
}

func (n *labNode) must(script string) string {
	n.t.Helper()
	out, err := n.sh(script)
	if err != nil {
		n.t.Fatalf("on w1: %v\n%s", err, out)
	}
	return out
}

func (n *labNode) fatal(t *testing.T, what, detail string, secrets ...string) {
	t.Helper()
	j := labRedact(n.tail("kevasod.service")+"\n"+n.tail(labUnit), secrets...)
	t.Fatalf("%s: %s\n--- journal ---\n%s", what, labRedact(detail, secrets...), j)
}

func (n *labNode) tail(unit string) string {
	out, _ := n.sh("journalctl -u " + sshboot.Quote(unit) + " -n 40 --no-pager -o cat")
	if len(out) > 4000 {
		out = out[len(out)-4000:]
	}
	return out
}

func (n *labNode) tcp(ip string) string {
	if net.ParseIP(ip).To4() == nil {
		return "ERROR"
	}
	out, err := n.sh("if timeout 4 bash -c 'echo >/dev/tcp/" + ip + "/6443'; then echo OPEN; else echo CLOSED; fi")
	if err != nil && !strings.Contains(out, "CLOSED") && !strings.Contains(out, "OPEN") {
		return "ERROR " + strings.TrimSpace(out)
	}
	if strings.Contains(out, "OPEN") {
		return "OPEN"
	}
	return "CLOSED"
}

type fileFact struct {
	missing     bool
	mode, owner string
	hash, mtime string
	inode       string
	raw         string
}

func (f fileFact) id() string {
	if f.missing {
		return "missing"
	}
	return f.hash + " inode " + f.inode
}

func (n *labNode) file(path string) (fileFact, error) {
	q := sshboot.Quote(path)
	out, err := n.sh("if [ -e " + q + " ]; then stat -c '%a %U %Y %i' " + q + "; sha256sum " + q + "; else echo MISSING; fi")
	f := fileFact{raw: strings.TrimSpace(out)}
	if strings.HasPrefix(f.raw, "MISSING") {
		f.missing = true
		return f, nil
	}
	if err != nil {
		return f, err
	}
	lines := strings.Split(f.raw, "\n")
	if len(lines) < 2 {
		return f, fmt.Errorf("stat: %s", f.raw)
	}
	st := strings.Fields(lines[0])
	sum := strings.Fields(lines[1])
	if len(st) < 4 || len(sum) < 1 {
		return f, fmt.Errorf("stat: %s", f.raw)
	}
	f.mode, f.owner, f.mtime, f.inode = st[0], st[1], st[2], st[3]
	f.hash = sum[0]
	return f, nil
}

type unitFact struct {
	state, sub, pid, restarts, result, started, mono, changed string
}

func (u unitFact) sameStart(o unitFact) bool {
	return u.pid == o.pid && u.started == o.started && u.mono == o.mono
}

func (n *labNode) unit(name string) unitFact {
	out, err := n.sh("systemctl show -p ActiveState -p SubState -p ExecMainPID -p NRestarts -p Result -p ActiveEnterTimestamp -p ActiveEnterTimestampMonotonic -p StateChangeTimestamp " + sshboot.Quote(name))
	if err != nil {
		return unitFact{state: "error", result: strings.TrimSpace(out)}
	}
	var u unitFact
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		switch k {
		case "ActiveState":
			u.state = v
		case "SubState":
			u.sub = v
		case "ExecMainPID":
			u.pid = v
		case "NRestarts":
			u.restarts = v
		case "Result":
			u.result = v
		case "ActiveEnterTimestamp":
			u.started = v
		case "ActiveEnterTimestampMonotonic":
			u.mono = v
		case "StateChangeTimestamp":
			u.changed = v
		}
	}
	return u
}

// holds reports when the credential file or the unit changes during d.
func (n *labNode) holds(d time.Duration, path string, f fileFact, u unitFact) error {
	end := time.Now().Add(d)
	for {
		got, err := n.file(path)
		if err != nil {
			return err
		}
		cur := n.unit(labUnit)
		switch {
		case got.missing:
			return fmt.Errorf("file removed (was %s)", f.id())
		case got.hash != f.hash || got.inode != f.inode || got.mtime != f.mtime:
			return fmt.Errorf("file changed: %s mtime %s (was %s mtime %s)", got.id(), got.mtime, f.id(), f.mtime)
		case !cur.sameStart(u):
			return fmt.Errorf("unit restarted: pid %s started %s (was pid %s started %s)", cur.pid, cur.started, u.pid, u.started)
		}
		if !time.Now().Before(end) {
			return nil
		}
		sleep := 5 * time.Second
		if left := time.Until(end); left < sleep {
			sleep = left
		}
		time.Sleep(sleep)
	}
}

func labCredentialPath(t *testing.T, n *labNode) string {
	t.Helper()
	out := n.must("systemctl cat " + sshboot.Quote(labUnit))
	m := regexp.MustCompile(`(?m)^LoadCredential=` + regexp.QuoteMeta(labSecret) + `:(\S+)\s*$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("unit has no LoadCredential for %s:\n%s", labSecret, out)
	}
	return m[1]
}

func labAwaitFile(t *testing.T, n *labNode, path, hash string, within time.Duration, secrets ...string) fileFact {
	t.Helper()
	var last fileFact
	deadline := time.Now().Add(within)
	for {
		got, err := n.file(path)
		if err == nil {
			last = got
			if !last.missing && last.hash == hash {
				return last
			}
		} else {
			last.raw = err.Error()
		}
		if time.Now().After(deadline) {
			n.fatal(t, "credential file", fmt.Sprintf("after %s: %s want sha256 %s", within, last.raw, hash), secrets...)
		}
		time.Sleep(2 * time.Second)
	}
}

func labAwaitStable(t *testing.T, n *labNode, secrets ...string) unitFact {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last unitFact
	for {
		last = n.unit(labUnit)
		time.Sleep(3 * time.Second)
		cur := n.unit(labUnit)
		if cur.state == "active" && cur.pid != "" && cur.pid != "0" && cur.sameStart(last) && cur.started != "" {
			return cur
		}
		last = cur
		if time.Now().After(deadline) {
			n.fatal(t, "plugin unit", fmt.Sprintf("not staying up: %+v", cur), secrets...)
		}
	}
}

type rotated struct {
	file fileFact
	unit unitFact
}

func labAwaitRotation(t *testing.T, n *labNode, path, hash, oldInode string, old unitFact, within time.Duration, secrets ...string) rotated {
	t.Helper()
	deadline := time.Now().Add(within)
	var last fileFact
	var u unitFact
	for {
		if got, err := n.file(path); err == nil {
			last = got
		}
		u = n.unit(labUnit)
		restarted := u.state == "active" && u.pid != "" && u.pid != "0" && !u.sameStart(old)
		if !last.missing && last.hash == hash && last.inode != "" && last.inode != oldInode && restarted {
			time.Sleep(3 * time.Second)
			u2 := n.unit(labUnit)
			f2, err := n.file(path)
			if err == nil && u2.sameStart(u) && !f2.missing && f2.hash == hash {
				return rotated{file: f2, unit: u2}
			}
			if err == nil {
				last = f2
			}
			u = u2
		}
		if time.Now().After(deadline) {
			n.fatal(t, "rotation", fmt.Sprintf("file %s unit pid %s started %q (was pid %s started %q inode %s)",
				last.id(), u.pid, u.started, old.pid, old.started, oldInode), secrets...)
		}
		time.Sleep(2 * time.Second)
	}
}

func labAwaitRemoval(t *testing.T, n *labNode, path string, old unitFact, ips []string, within time.Duration, secrets ...string) unitFact {
	t.Helper()
	deadline := time.Now().Add(within)
	var last fileFact
	var u unitFact
	for _, ip := range ips {
		if st := n.tcp(ip); st != "OPEN" {
			t.Logf("after the cut was removed, %s is %s", ip, st)
		}
	}
	for {
		if got, ferr := n.file(path); ferr == nil {
			last = got
		}
		u = n.unit(labUnit)
		if last.missing && !u.sameStart(old) {
			return u
		}
		if time.Now().After(deadline) {
			n.fatal(t, "back in contact", fmt.Sprintf("file %s unit state %s pid %s started %q (was pid %s started %q)",
				last.id(), u.state, u.pid, u.started, old.pid, old.started), secrets...)
		}
		time.Sleep(2 * time.Second)
	}
}

// labAPIAddrs is every IPv4 the worker's kevasod dials for the API, plus the
// system node's internal address, except addresses that belong to w1 itself.
func labAPIAddrs(t *testing.T, n *labNode, internal string) []string {
	t.Helper()
	out := n.must("systemctl cat kevasod; echo ---; cat /var/lib/kevaso/pki/servers 2>/dev/null || true")
	seen := map[string]bool{}
	var ips []string
	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip == "" || n.ownAddrs[ip] || seen[ip] {
			return
		}
		if net.ParseIP(ip).To4() == nil {
			return
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	add(internal)
	for _, m := range regexp.MustCompile(`https://([0-9.]+)(?::[0-9]+)?`).FindAllStringSubmatch(out, -1) {
		add(m[1])
	}
	if len(ips) == 0 {
		t.Fatalf("no system-node address to cut off (internal %q)", internal)
	}
	return ips
}

func labCutScript(ips []string) string {
	var in, out []string
	for _, ip := range ips {
		if net.ParseIP(ip).To4() == nil {
			continue
		}
		in = append(in, "ip saddr "+ip+" drop")
		out = append(out, "ip daddr "+ip+" drop")
	}
	return "nft -f - <<'NFT'\ntable inet kvt-cut {\n  chain in { type filter hook input priority -10; " +
		strings.Join(in, "; ") + "; }\n  chain out { type filter hook output priority -10; " +
		strings.Join(out, "; ") + "; }\n}\nNFT\n"
}

func labArch(t *testing.T, n *labNode) string {
	t.Helper()
	switch u := strings.TrimSpace(n.must("uname -m")); u {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	default:
		t.Fatalf("w1 cpu %s", u)
		return ""
	}
}

func labBuildPlugin(t *testing.T, arch string) (bin, manifest string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}")
	cmd.Env = append(os.Environ(), "GOPROXY=off")
	rootb, err := cmd.Output()
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	root := strings.TrimSpace(string(rootb))
	bin = filepath.Join(t.TempDir(), "kvtcs")
	build := exec.Command("go", "build", "-o", bin, "kevaso.com/core/test/e2e/testdata/kvtcs")
	build.Dir = root
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOPROXY=off")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v\n%s", err, b)
	}
	manifest = filepath.Join(root, "test", "e2e", "testdata", "kvtcs", "kevaso-plugin.json")
	return bin, manifest
}

func labValueFiles(t *testing.T, a, b string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return write("a", a), write("b", b)
}

func labHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var labInviteCode = regexp.MustCompile(`kvi_\S+`)

func labRedact(s string, secrets ...string) string {
	s = labInviteCode.ReplaceAllString(s, "kvi_…")
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[value]")
		}
	}
	return s
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 240 {
		s = s[:240]
	}
	return s
}

func labKvo(t *testing.T, ctx context.Context, stdin string, args ...string) string {
	t.Helper()
	out, code := labKvoCode(ctx, stdin, args...)
	if code != 0 {
		t.Fatalf("kvo %v: exit %d\n%s", args, code, labRedact(out))
	}
	return out
}

func labKvoCode(ctx context.Context, stdin string, args ...string) (string, int) {
	var o bytes.Buffer
	code := kvo.Run(ctx, args, strings.NewReader(stdin), &o, &o)
	return o.String(), code
}

func labKvoadm(t *testing.T, ctx context.Context, labDir string, args ...string) string {
	t.Helper()
	home := os.Getenv("HOME")
	if err := os.Setenv("HOME", labDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Setenv("HOME", home) }()
	var o bytes.Buffer
	code := kvoadm.Run(ctx, args, strings.NewReader(""), &o, &o)
	if code != 0 {
		t.Fatalf("kvoadm %s: exit %d\n%s", labCmd(args), code, labRedact(o.String()))
	}
	return o.String()
}

func labKvoadmCode(ctx context.Context, labDir string, args ...string) (string, int) {
	home := os.Getenv("HOME")
	_ = os.Setenv("HOME", labDir)
	defer func() { _ = os.Setenv("HOME", home) }()
	var o bytes.Buffer
	code := kvoadm.Run(ctx, args, strings.NewReader(""), &o, &o)
	return labRedact(o.String()), code
}

func labCmd(args []string) string {
	n := 2
	if len(args) < n {
		n = len(args)
	}
	return strings.Join(args[:n], " ")
}

func jsonObject(s string) string {
	i := strings.Index(s, "{")
	j := strings.LastIndex(s, "}")
	if i >= 0 && j > i {
		return s[i : j+1]
	}
	return s
}
