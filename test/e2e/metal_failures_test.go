//go:build metal

package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/sdk/kri"
)

// TestMetalKilledMidStart is kevasod killed with SIGKILL while it starts a microVM: systemd
// starts it again (Restart=always), the silo ends up Running, with exactly one VMM.
//
// Listens on nothing outside.
func TestMetalKilledMidStart(t *testing.T) {
	c := metal(t)
	ns := "killed"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080))
	c.eventually("the silo is being started", 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "vm")
		return s.Status.Phase == "Starting" || s.Status.Phase == "Scheduled" && s.Status.Host != "", s.Status.Phase
	})
	time.Sleep(3 * time.Second)
	c.mustSh("systemctl kill -s KILL kevasod")
	t.Log("kevasod killed (SIGKILL) while the microVM starts")
	c.eventually("the API is back", 3*time.Minute, func() (bool, string) { out, code := c.kvo("", "get", "hosts"); return code == 0, out })
	c.waitRunning(ns, 15*time.Minute, "vm")
	s := c.silo(ns, "vm")
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID})
	if got := strings.TrimSpace(c.mustSh("pgrep -f -c -- " + n.Socket + " || true")); got != "1" {
		t.Errorf("%s VMM processes for the silo, want 1", got)
	}
	c.expect("it answers", func() string { o, _ := c.in(ns, "vm", "echo alive"); return o }(), "alive")
}

// TestMetalDownloadInterrupted is a disk image download cut off midway (kevasod killed while it
// fetches an image the host doesn't have): the next try starts over and verifies, the silo
// runs, and no partial download is left behind.
//
// Listens on nothing outside.
func TestMetalDownloadInterrupted(t *testing.T) {
	c := metal(t)
	ns := "download"
	c.namespace(ns)
	url, _ := ubuntuRelease(t, c.uname)
	// A minimal image this host hasn't fetched (the release one may be cached by TestMetalImages).
	url = strings.Replace(url, "server-cloudimg", "minimal-cloudimg", 1)
	url = strings.Replace(url, "https://cloud-images.ubuntu.com/releases/", "https://cloud-images.ubuntu.com/minimal/releases/", 1)
	sum := minimalSum(t, url)
	_ = c.mustSh("rm -f " + cloudhypervisor.ImagesDir + "/*" + sum[:12] + "* 2>/dev/null; true")
	c.apply(fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: vm, namespace: %s }
spec:
  runtime: cloud-hypervisor
  vm: { disk: { url: %s, sha256: %s } }
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
`, ns, url, sum))
	c.eventually("the download has begun", 5*time.Minute, func() (bool, string) {
		out, _ := c.sh("ls -l " + cloudhypervisor.ImagesDir + " | grep -c '\\.download' || true")
		return strings.TrimSpace(out) != "0", out
	})
	c.mustSh("sleep 2; systemctl kill -s KILL kevasod")
	t.Log("kevasod killed mid download")
	c.waitRunning(ns, 20*time.Minute, "vm")
	if out := c.mustSh("ls " + cloudhypervisor.ImagesDir + " | grep '\\.download' || true"); strings.TrimSpace(out) != "" {
		t.Errorf("a partial download is left: %s", out)
	}
	c.expect("the image is the minimal one", func() string { o, _ := c.in(ns, "vm", "cat /etc/os-release"); return o }(), "noble")
}

// minimalSum is the SHA-256 Ubuntu publishes for a minimal image.
func minimalSum(t *testing.T, url string) string {
	t.Helper()
	i := strings.LastIndex(url, "/")
	dir, file := url[:i+1], url[i+1:]
	code, body, err := fromMac(dir+"SHA256SUMS", "", time.Minute)
	if err != nil || code != 200 {
		t.Fatalf("%sSHA256SUMS: %d %v", dir, code, err)
	}
	for _, l := range strings.Split(body, "\n") {
		if m := sumsLine.FindStringSubmatch(strings.TrimSpace(l)); m != nil && m[2] == file {
			return m[1]
		}
	}
	t.Fatalf("%s isn't in %sSHA256SUMS", file, dir)
	return ""
}

// TestMetalBadImages is a silo whose image doesn't exist and one whose registry can't be
// reached: each says why (ImagePullFailed and the engine's words), and neither retries hot.
//
// Listens on nothing outside.
func TestMetalBadImages(t *testing.T) {
	c := metal(t)
	ns := "badimg"
	c.namespace(ns)
	box := func(name, image string) string {
		return fmt.Sprintf("apiVersion: kevaso/v1\nkind: Silo\nmetadata: { name: %s, namespace: %s }\nspec:\n  runtime: docker\n  container: { image: %s }\n  resources: { cpu: 1, memory: 64Mi }\n", name, ns, image)
	}
	since := strings.TrimSpace(c.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	c.apply(box("missing", "docker.io/library/kvt-no-such-image:never") + "---\n" + box("unreachable", "192.0.2.1:5000/kvt/x:1"))
	for _, s := range []struct{ name, why string }{{"missing", "ImagePullFailed"}, {"unreachable", "ImagePullFailed"}} {
		c.eventually(s.name+": the reason is said", 5*time.Minute, func() (bool, string) {
			si := c.silo(ns, s.name)
			for _, cd := range si.Status.Conditions {
				if cd.Reason == s.why {
					t.Logf("%s: %s", s.name, cd.Message)
					return si.Status.Phase != "Running", cd.Message
				}
			}
			return false, fmt.Sprint(si.Status.Phase, si.Status.Conditions)
		})
	}
	time.Sleep(2 * time.Minute)
	for _, img := range []string{"kvt-no-such-image", "192.0.2.1:5000"} {
		n, _ := strconv.Atoi(strings.TrimSpace(c.mustSh(fmt.Sprintf("journalctl -u kevasod --no-pager --since '%s' | grep -c -F '%s' || true", since, img))))
		// A few tries a minute at most; hot looping would be hundreds.
		if n > 40 {
			t.Errorf("%s: %d log lines in about 3 minutes: retrying hot", img, n)
		} else {
			t.Logf("%s: %d log lines in about 3 minutes", img, n)
		}
	}
}
