//go:build metal

package e2e

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/internal/operators"
)

// TestMetalSecretKeys is a Secret with named keys (hack/design/secret-keys.md), every reference
// naming its key, in a microVM and in a container: every key ("*") as files in a folder and as
// PREFIX_KEY variables, one key as a file and as one variable, one key injected by the egress gate,
// the endpoint answering one key or every key (/v1/secrets/NAME/*) and refusing a bare
// /v1/secrets/NAME; then one key rotated and one removed, reaching each delivery. Admission refuses
// a reference without a key, "*" for inject, and a key the secret doesn't have. And a ClusterSecret
// with keys, which a plugin's unit loads through systemd as NAME_KEY credentials, a rotated key
// restarting it.
func TestMetalSecretKeys(t *testing.T) {
	c := metal(t)
	ns := "keys"
	c.namespace(ns, "grant/vmkeys", "grant/boxkeys", "secret/db", "secret/api")
	user, pw, pw2 := randomValue(t, "u-"), randomValue(t, "pw-"), randomValue(t, "pw2-")
	tok, id := randomValue(t, "sk-"), randomValue(t, "id-")
	dir := t.TempDir()
	file := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// A value without its key is refused by kvo, showing the form.
	if out, code := c.kvo(pw, "create", "secret", "nokey", "-n", ns, "--from-file", "-"); code == 0 || !strings.Contains(out, "--from-file KEY=") {
		t.Fatalf("--from-file - without a key: exit %d %s", code, out)
	}
	out := c.must("", "create", "secret", "db", "-n", ns, "--from-file", "username="+file("u", user), "--from-file", "password="+file("p", pw))
	c.expect("create names the keys", out, "keys password, username")
	c.must("", "create", "secret", "api", "-n", ns, "--from-file", "token="+file("t", tok), "--from-file", "id="+file("i", id))
	c.expect("describe lists the keys, not the values", c.must("", "describe", "secret", "db", "-n", ns), "password, username")
	if out, code := c.kvo("", "get", "secret", "db", "-n", ns, "--reveal"); code == 0 || !strings.Contains(out, "--key") {
		t.Fatalf("--reveal without --key: exit %d %s", code, out)
	}

	// References without a key, "*" for an inject, and a key the secret doesn't have: refused.
	bad := func(entry string) string {
		return `apiVersion: kevaso/v1
kind: Grant
metadata: { name: bad, namespace: ` + ns + ` }
spec:
  secrets: [` + entry + `]
`
	}
	inject := "deliver: inject, to: { host: " + metalInetName + " }"
	for _, r := range []struct{ what, entry, want string }{
		{"an inject without a key", "{ name: api, " + inject + " }", "name the one key to inject"},
		{`an inject of "*"`, `{ name: api, key: "*", ` + inject + " }", `not "*"`},
		{"a file without a key", "{ name: db, deliver: file }", `every key (key: "*")`},
		{"a broker entry without a key", "{ name: db }", "key is required"},
		{"an unknown key", "{ name: api, key: nope }", `has no key "nope"`},
	} {
		if out, code := c.kvo(bad(r.entry), "apply", "-f", "-"); code == 0 || !strings.Contains(out, r.want) {
			t.Fatalf("%s: exit %d %s", r.what, code, out)
		}
	}

	grant := func(name string) string {
		return `apiVersion: kevaso/v1
kind: Grant
metadata: { name: ` + name + `, namespace: ` + ns + ` }
spec:
  egress: [{ to: "` + metalInetAddr + `/32", ports: ["443"] }]
  secrets:
    - { name: db, key: "*" }
    - { name: api, key: id }
    - { name: api, key: token, ` + inject + ` }
    - { name: db, key: "*", deliver: file }
    - { name: db, key: password, deliver: file, path: /run/pg/password }
    - { name: api, key: id, deliver: file }
    - { name: db, key: "*", deliver: env }
    - { name: db, key: password, deliver: env, env: PGPASSWORD }
    - { name: api, key: id, deliver: env }
`
	}
	c.apply(grant("vmkeys") + "---\n" + grant("boxkeys") + `---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: vm, namespace: ` + ns + ` }
spec:
  runtime: cloud-hypervisor
  vm: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
  grants: [vmkeys]
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: box, namespace: ` + ns + ` }
spec:
  runtime: docker
  container: { image: ` + metalShell + `, command: [sh, -c, "while :; do sleep 3600; done"] }
  resources: { cpu: 1, memory: 256Mi }
  grants: [boxkeys]
`)
	c.waitRunning(ns, 20*time.Minute, "vm", "box")

	const local = "-H 'Kevaso-Local: 1'"
	envOf := func(silo, name string) string {
		if silo == "box" { // through Kevaso's OCI runtime: the main process's environment
			o, _ := c.in(ns, silo, `tr '\0' '\n' < /proc/1/environ | sed -n 's/^`+name+`=//p'`)
			return o
		}
		o, _ := c.in(ns, silo, `set -a; . /run/kevaso/secrets.env; printf '%s' "$`+name+`"`)
		return o
	}
	for _, silo := range []string{"vm", "box"} {
		t.Run(silo, func(t *testing.T) {
			c := &mt{metalSuite: c.metalSuite, t: t, ctx: c.ctx}
			in := func(script string) string { o, _ := c.in(ns, silo, script); return o }
			ep := func(path string) string {
				return in("curl -sS --max-time 10 -w ' %{http_code}' " + local + " 'http://169.254.42.1" + path + "' 2>&1")
			}
			c.expect("the endpoint: one key", ep("/v1/secrets/db/password"), pw+" 200")
			all := ep("/v1/secrets/db/*")
			c.expect("the endpoint: every key, as JSON (username)", all, `"username":"`+b64(user)+`"`)
			c.expect("the endpoint: every key, as JSON (password)", all, `"password":"`+b64(pw)+`"`)
			c.expect("the endpoint: no key named is refused, showing both forms", ep("/v1/secrets/db"), "/v1/secrets/db/* for every key")
			c.expect("the endpoint: no key named is a 400", ep("/v1/secrets/db"), " 400")
			c.expect("a grant naming one key: that key", ep("/v1/secrets/api/id"), id+" 200")
			some := ep("/v1/secrets/api/*")
			c.expect(`a grant naming one key: "*" is that key alone`, some, `"id":"`+b64(id)+`"`)
			if strings.Contains(some, b64(tok)) || strings.Contains(some, `"token"`) {
				t.Errorf(`/v1/secrets/api/* gave a key the grant doesn't name: %s`, some)
			}
			c.expect("a key the grant doesn't give: none", ep("/v1/secrets/api/token"), " 404")

			// Files and variables the host wrote.
			c.expect(`"*" as a folder: username`, in("cat /run/secrets/db/username"), user)
			c.expect(`"*" as a folder: password`, in("cat /run/secrets/db/password; echo; stat -c '%a %U' /run/secrets/db/password"), pw+"\n400 root")
			c.expect("one key at its own path", in("cat /run/pg/password"), pw)
			c.expect("one key at its default path, /run/secrets/NAME/KEY", in("cat /run/secrets/api/id"), id)
			c.expect(`"*" as variables: DB_USERNAME`, envOf(silo, "DB_USERNAME"), user)
			c.expect(`"*" as variables: DB_PASSWORD`, envOf(silo, "DB_PASSWORD"), pw)
			c.expect("one key, named", envOf(silo, "PGPASSWORD"), pw)
			c.expect("one key, its default name NAME_KEY", envOf(silo, "API_ID"), id)

			// The injected key: the stand-in API sees it (as a hash), the silo never does.
			ca := `ca=; [ -f /etc/ssl/certs/kevaso-ca-bundle.crt ] && ca="--cacert /etc/ssl/certs/kevaso-ca-bundle.crt"; `
			got := in(ca + "curl -sS --max-time 15 $ca --resolve " + metalInetName + ":443:203.0.113.9 https://" + metalInetName + "/v1/models 2>&1")
			c.expect("the gate injects the key named", got, `"auth": "`+metalHash("Bearer "+tok)+`"`)
			if leaked := in("grep -rl -F -e '" + tok + "' /run /etc /root /tmp 2>/dev/null | head -3; env | grep -c -F -e '" + tok + "' || true"); strings.TrimSpace(leaked) != "0" {
				t.Errorf("the injected key is in the silo: %q", leaked)
			}
		})
	}

	// One key rotated: every delivery of it changes in both silos, the other key stays.
	c.must(pw2, "secret", "set", "db", "-n", ns, "--from-file", "password=-")
	c.expect("the other key kept", c.must("", "get", "secret", "db", "-n", ns, "--reveal", "--key", "username"), user)
	c.expect(`--reveal --key "*": every key`, c.must("", "get", "secret", "db", "-n", ns, "--reveal", "--key", "*"), "password: "+pw2+"\nusername: "+user)
	for _, silo := range []string{"vm", "box"} {
		in := func(script string) string { o, _ := c.in(ns, silo, script); return o }
		c.eventually(silo+": the rotated key in the folder and at its own path", 2*time.Minute, func() (bool, string) {
			got := in("cat /run/secrets/db/password; echo; cat /run/pg/password; echo; cat /run/secrets/db/username")
			return got == pw2+"\n"+pw2+"\n"+user, got
		})
		c.expect(silo+": the endpoint after rotation", in("curl -sS "+local+" http://169.254.42.1/v1/secrets/db/password"), pw2)
		if silo == "vm" {
			c.eventually("vm: the rotated key as variables", time.Minute, func() (bool, string) {
				got := envOf("vm", "DB_PASSWORD") + " " + envOf("vm", "PGPASSWORD")
				return got == pw2+" "+pw2, got
			})
		}
	}
	// A key removed goes from the folder, the variables and the endpoint's "*".
	c.must("", "secret", "set", "db", "-n", ns, "--remove-key", "username")
	for _, silo := range []string{"vm", "box"} {
		c.eventually(silo+": a removed key's file is gone", 2*time.Minute, func() (bool, string) {
			o, _ := c.in(ns, silo, "ls /run/secrets/db")
			return strings.TrimSpace(o) == "password", o
		})
		o, _ := c.in(ns, silo, "curl -sS "+local+" 'http://169.254.42.1/v1/secrets/db/*'")
		if strings.Contains(o, "username") || !strings.Contains(o, `"password":"`+b64(pw2)+`"`) {
			t.Errorf("%s: /v1/secrets/db/* after the removal: %s", silo, o)
		}
		if silo == "vm" {
			c.eventually("vm: a removed key's variable is gone", time.Minute, func() (bool, string) {
				got := envOf("vm", "DB_USERNAME")
				return got == "", got
			})
		}
	}

	t.Run("plugin", func(t *testing.T) { metalClusterSecretKeysPlugin(&mt{metalSuite: c.metalSuite, t: t, ctx: c.ctx}) })
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// metalClusterSecretKeysPlugin: a ClusterSecret with keys, installed for a plugin's node side.
// kevasod keeps it as a folder (one file per key, 0600 root); systemd loads each as NAME_KEY.
func metalClusterSecretKeysPlugin(c *mt) {
	t := c.t
	const plugin, secret = "kvtcs", "kvtcs-keys"
	unit := "kevaso-plugin-" + plugin + "-node.service"
	a, b, b2 := randomValue(t, "a-"), randomValue(t, "b-"), randomValue(t, "b2-")
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c.must("", "create", "clustersecret", secret, "--from-file", "access-key="+write("a", a), "--from-file", "secret-key="+write("b", b))
	c.apply(fmt.Sprintf(`apiVersion: kevaso/v1
kind: ClusterRole
metadata: { name: %[1]s }
rules:
  - { verbs: [get], resources: [clustersecrets/value], resourceNames: [%[1]s] }
---
apiVersion: kevaso/v1
kind: ClusterRoleBinding
metadata: { name: %[1]s }
roleRef: { kind: ClusterRole, name: %[1]s }
subjects:
  - { kind: ServiceAccount, name: %[2]s, namespace: %[3]s }
`, secret, operators.ServiceAccountNodeName(plugin), v1.PluginNamespace))

	bin := filepath.Join(t.TempDir(), plugin)
	build := exec.CommandContext(c.ctx, "go", "build", "-o", bin, "kevaso.com/core/test/e2e/testdata/kvtcs")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+c.arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the plugin: %v\n%s", err, out)
	}
	ssh := []string{c.cfg.SSHTarget(), "--ssh-port", strconv.Itoa(c.cfg.Port), "--ssh-key", c.cfg.KeyFile, "--host-key", c.cfg.HostKey}
	adm := func(args ...string) (string, int) {
		var o bytes.Buffer
		code := kvoadm.Run(c.ctx, args, strings.NewReader(""), &o, &o)
		return o.String(), code
	}
	if out, code := adm(append(append([]string{"plugin", "install"}, ssh...), "--name", plugin, "--binary", bin, "--side", "node",
		"--manifest", "testdata/kvtcs/kevaso-plugin.json", "--cluster-secret", secret)...); code != 0 {
		t.Fatalf("plugin install: exit %d\n%s", code, out)
	}
	t.Cleanup(func() {
		if out, code := adm(append(append([]string{"plugin", "remove"}, ssh...), "--name", plugin, "--side", "node")...); code != 0 {
			t.Logf("plugin remove: exit %d %s", code, out)
		}
		c.kvo("", "delete", "clusterrolebinding", secret)
		c.kvo("", "delete", "clusterrole", secret)
		c.kvo("", "delete", "clustersecret", secret)
	})
	folder := "/etc/kevaso/plugins/" + plugin + "/" + secret
	sums := func(paths ...string) string {
		out, _ := c.sh("for f in " + strings.Join(paths, " ") + "; do if [ -f $f ]; then stat -c '%a %U' $f; sha256sum < $f | cut -c1-64; else echo missing; fi; done")
		return strings.TrimSpace(out)
	}
	want := func(vals ...string) string {
		var w []string
		for _, v := range vals {
			w = append(w, "600 root", labHash(v))
		}
		return strings.Join(w, "\n")
	}
	creds := "/run/credentials/" + unit
	c.eventually("the folder, one file per key", 2*time.Minute, func() (bool, string) {
		got := sums(folder+"/access-key", folder+"/secret-key")
		return got == want(a, b), got
	})
	credSums := func() string {
		out, _ := c.sh("for k in access-key secret-key; do f=" + creds + "/" + secret + "_$k; [ -f $f ] && sha256sum < $f | cut -c1-64 || echo missing; done; systemctl show -p ActiveEnterTimestampMonotonic --value " + unit)
		return strings.TrimSpace(out)
	}
	var started string
	c.eventually("systemd loads each key as NAME_KEY", 2*time.Minute, func() (bool, string) {
		got := strings.Split(credSums(), "\n")
		if len(got) == 3 && got[0] == labHash(a) && got[1] == labHash(b) {
			started = got[2]
			return true, ""
		}
		return false, strings.Join(got, " ")
	})
	t.Logf("%s holds %s_access-key and %s_secret-key", creds, secret, secret)

	// One key rotated: rewritten, the unit restarted onto it, the other key unchanged.
	c.must(b2, "set", "clustersecret", secret, "--from-file", "secret-key=-")
	c.eventually("the rotated key reaches the unit's credentials", 2*time.Minute, func() (bool, string) {
		got := strings.Split(credSums(), "\n")
		return len(got) == 3 && got[0] == labHash(a) && got[1] == labHash(b2) && got[2] != started, strings.Join(got, " ")
	})
	c.expect("the folder after rotation", sums(folder+"/access-key", folder+"/secret-key"), want(a, b2))
}
