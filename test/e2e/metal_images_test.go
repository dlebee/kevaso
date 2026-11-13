//go:build metal

package e2e

import (
	"bufio"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// metalBusybox is the public image the registry part pulls (small, and pulled by nothing else
// in the suite, so its pulls are this test's own).
const metalBusybox = "docker.io/library/busybox:1.36"

// TestMetalImages is what a silo starts from (ADR 0011), from the real registries and mirrors:
// container.image from Docker Hub by tag, then, with the image removed from the host, by the
// digest the tag pulled; vm.image built in (ubuntu-24.04); vm.disk inline with the SHA-256
// Ubuntu publishes for it; the same disk with a wrong hash, refused with the reason.
//
// Listens on nothing outside.
func TestMetalImages(t *testing.T) {
	c := metal(t)
	ns := "images"
	c.namespace(ns)
	box := func(name, image string) string {
		return fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: %s, namespace: %s }
spec:
  runtime: docker
  container: { image: %s, command: [sh, -c, "while :; do sleep 3600; done"] }
  resources: { cpu: 1, memory: 64Mi }
`, name, ns, image)
	}

	// By tag, from a host that doesn't have it.
	c.mustSh(`docker image rm -f $(docker image ls -q busybox) >/dev/null 2>&1; true`)
	c.apply(box("bytag", metalBusybox))
	c.waitRunning(ns, 10*time.Minute, "bytag")
	repoDigest := strings.TrimSpace(c.mustSh(`docker image inspect --format '{{index .RepoDigests 0}}' ` + metalBusybox))
	_, digest, ok := strings.Cut(repoDigest, "@")
	if !ok || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("the pulled image's digest: %q", repoDigest)
	}
	t.Logf("by tag: pulled %s", repoDigest)
	if st := c.silo(ns, "bytag").Status.Image; st == nil || st.Digest != digest {
		t.Errorf("status.image of bytag: %+v, want digest %s", st, digest)
	}
	c.expect("the image is busybox", func() string { o, _ := c.in(ns, "bytag", "busybox | head -1"); return o }(), "BusyBox v1.36")

	// By that digest, with the image gone from the host first: a real pull by digest.
	c.must("", "delete", "silo", "bytag", "-n", ns)
	c.eventually("bytag is gone", 3*time.Minute, func() (bool, string) {
		out, _ := c.kvo("", "get", "silos", "-n", ns, "-o", "json")
		return len(metalSilos(out)) == 0, out
	})
	c.mustSh(`docker image rm -f $(docker image ls -q busybox) >/dev/null 2>&1; true`)
	if left := strings.TrimSpace(c.mustSh(`docker image ls -q busybox`)); left != "" {
		t.Fatalf("busybox still on the host: %s", left)
	}
	c.apply(box("bydigest", "docker.io/library/busybox@"+digest))
	c.waitRunning(ns, 10*time.Minute, "bydigest")
	c.expect("by digest: the host pulled that digest", c.mustSh(`docker image ls --digests --format '{{.Repository}}@{{.Digest}}' busybox`), "busybox@"+digest)
	if st := c.silo(ns, "bydigest").Status.Image; st == nil || st.Digest != digest {
		t.Errorf("status.image of bydigest: %+v", st)
	}

	// vm.image, built in.
	c.apply(vmEcho(ns, "builtin", 8080))
	// vm.disk inline, with the hash Ubuntu publishes (read here, over HTTPS).
	url, sum := ubuntuRelease(t, c.uname)
	vm := func(name, sha string) string {
		return fmt.Sprintf(`---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: %s, namespace: %s }
spec:
  runtime: cloud-hypervisor
  vm: { disk: { url: %s, sha256: %s } }
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
`, name, ns, url, sha)
	}
	wrong := sum[:len(sum)-1] + string("0123456789abcdef"[(strings.IndexByte("0123456789abcdef", sum[len(sum)-1])+1)%16])
	c.apply(vm("inline", sum))
	c.waitRunning(ns, 25*time.Minute, "builtin", "inline")
	c.expect("vm.image: Ubuntu 24.04", func() string { o, _ := c.in(ns, "builtin", "cat /etc/os-release"); return o }(), "VERSION_ID=\"24.04\"")
	c.expect("vm.disk: the release image", func() string { o, _ := c.in(ns, "inline", "cat /etc/os-release"); return o }(), "noble")
	if st := c.silo(ns, "inline").Status.Image; st == nil || !strings.Contains(st.Ref, sum) {
		t.Errorf("status.image of inline: %+v, want a ref with its sha256", st)
	}
	// The same disk with a wrong hash (after the right one, so the two never download at once).
	c.apply(vm("wronghash", wrong))
	c.eventually("a wrong hash is refused, saying so", 15*time.Minute, func() (bool, string) {
		s := c.silo(ns, "wronghash")
		d, _ := c.kvo("", "describe", "silo", "wronghash", "-n", ns)
		return s.Status.Phase != "Running" && strings.Contains(d, "want "+wrong), d
	})
}

var sumsLine = regexp.MustCompile(`^([0-9a-f]{64}) \*?(\S+)$`)

// ubuntuRelease is the noble release cloud image for the machine's CPU and its published SHA-256.
func ubuntuRelease(t *testing.T, uname string) (url, sum string) {
	t.Helper()
	arch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[uname]
	const dir = "https://cloud-images.ubuntu.com/releases/noble/release/"
	file := "ubuntu-24.04-server-cloudimg-" + arch + ".img"
	client := &http.Client{Timeout: time.Minute}
	resp, err := client.Get(dir + "SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	if resp.StatusCode != 200 {
		t.Fatalf("SHA256SUMS: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if m := sumsLine.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil && m[2] == file {
			return dir + file, m[1]
		}
	}
	t.Fatalf("%s isn't in %sSHA256SUMS", file, dir)
	return "", ""
}
