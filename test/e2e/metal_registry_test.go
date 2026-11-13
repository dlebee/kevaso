//go:build metal

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// metalRegistryDir holds the test registry's htpasswd on the machine (removed by the suite's reset).
const metalRegistryDir = "/var/lib/kvt-registry"

// TestMetalRegistry is a private registry pull (ADR 0011, the images work): a registry:2 with
// basic auth made for the test runs on the machine (127.0.0.1:5000, Docker's default insecure
// range, so no certificate is needed), the test pushes an image there, and a silo whose
// container.pull names a registry Secret pulls it; a silo without the secret is refused with
// ImagePullFailed. The credential never lands in Docker's own config on the host.
//
// Listens on nothing outside (the registry is on loopback).
func TestMetalRegistry(t *testing.T) {
	c := metal(t)
	ns := "reg"
	c.namespace(ns, "secret/regcred")
	user, pass := "kvt", randomValue(t, "reg-")
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = c.sh("docker rm -f kvt-registry >/dev/null 2>&1; rm -rf " + metalRegistryDir + " /root/.kvt-push")
	})
	if _, err := c.d.Run(c.ctx, "mkdir -p "+metalRegistryDir+" && cat > "+metalRegistryDir+"/htpasswd", []byte(user+":"+string(hash)+"\n")); err != nil {
		t.Fatal(err)
	}
	c.mustSh(`docker rm -f kvt-registry >/dev/null 2>&1; docker run -d --name kvt-registry --network host --label kvt-e2e=1 \
  -e REGISTRY_HTTP_ADDR=127.0.0.1:5000 -e REGISTRY_AUTH=htpasswd -e REGISTRY_AUTH_HTPASSWD_REALM=kvt \
  -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd -v ` + metalRegistryDir + `:/auth:ro docker.io/library/registry:2.8.3 >/dev/null`)
	c.eventually("the test registry answers (and asks for a login)", time.Minute, func() (bool, string) {
		out, _ := c.sh("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/v2/")
		return strings.TrimSpace(out) == "401", out
	})
	// Push an image there, logged in with a config of the test's own (never root's), then drop
	// every local copy so Kevaso's pull is a real one.
	if out, err := c.d.Run(c.ctx, `set -e; d=/root/.kvt-push; rm -rf $d; mkdir -m 700 $d
docker --config $d login -u `+user+` --password-stdin 127.0.0.1:5000 >/dev/null
docker pull -q docker.io/library/busybox:1.36 >/dev/null
docker tag docker.io/library/busybox:1.36 127.0.0.1:5000/kvt/busy:1
docker --config $d push -q 127.0.0.1:5000/kvt/busy:1 >/dev/null
docker --config $d logout 127.0.0.1:5000 >/dev/null; rm -rf $d
docker image rm -f 127.0.0.1:5000/kvt/busy:1 >/dev/null`, []byte(pass)); err != nil {
		t.Fatalf("push to the test registry: %v\n%s", err, out)
	}

	c.must(pass, "create", "secret", "regcred", "-n", ns, "--type", "registry", "--server", "127.0.0.1:5000", "--username", user, "--from-file", "-")
	box := func(name, pull string) string {
		return fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: %s, namespace: %s }
spec:
  runtime: docker
  container: { image: 127.0.0.1:5000/kvt/busy:1, %scommand: [sh, -c, "while :; do sleep 3600; done"] }
  resources: { cpu: 1, memory: 64Mi }
`, name, ns, pull)
	}
	c.apply(box("private", "pull: { secretRef: regcred }, "))
	c.waitRunning(ns, 10*time.Minute, "private")
	c.expect("the private image runs", func() string { o, _ := c.in(ns, "private", "busybox | head -1"); return o }(), "BusyBox v1.36")
	if out, _ := c.sh(`grep -rl -F -e "$(printf '%s' '` + pass[:len(pass)/2] + `')""$(printf '%s' '` + pass[len(pass)/2:] + `')" /root/.docker /etc/docker /run/kevaso-pull 2>/dev/null | head -3; true`); strings.TrimSpace(out) != "" {
		t.Errorf("the registry password is on the host: %s", out)
	} else {
		t.Log("the registry password isn't in Docker's config or a leftover auth file on the host")
	}

	c.mustSh("docker image rm -f 127.0.0.1:5000/kvt/busy:1 >/dev/null 2>&1; true")
	c.apply(box("anon", ""))
	c.eventually("without the secret: ImagePullFailed", 3*time.Minute, func() (bool, string) {
		s := c.silo(ns, "anon")
		for _, cd := range s.Status.Conditions {
			if cd.Reason == "ImagePullFailed" {
				return s.Status.Phase != "Running", cd.Message
			}
		}
		return false, fmt.Sprint(s.Status.Phase, s.Status.Conditions)
	})
}
