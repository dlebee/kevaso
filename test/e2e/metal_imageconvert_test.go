//go:build metal

package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestMetalCraftedDiskImageIsRefused places a qcow2 that names a backing file where a silo's
// disk image is fetched from, and the silo does not run. The file is already on the machine, so
// nothing is downloaded.
func TestMetalCraftedDiskImageIsRefused(t *testing.T) {
	c := metal(t)
	ns := "imgconvert"
	c.namespace(ns)
	img := craftedQcow2()
	sum := sha256.Sum256(img)
	digest := hex.EncodeToString(sum[:])
	path := "/var/lib/kevaso-images/sha256-" + digest + ".img"
	c.mustSh("mkdir -p /var/lib/kevaso-images && umask 077 && cat > " + path + " <<'EOF'\n" + base64.StdEncoding.EncodeToString(img) + "\nEOF\nbase64 -d " + path + " > " + path + ".raw && mv " + path + ".raw " + path + " && chmod 0600 " + path)
	t.Cleanup(func() { _, _ = c.sh("rm -f " + path) })
	c.apply(fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: crafted, namespace: %s }
spec:
  runtime: cloud-hypervisor
  vm: { disk: { url: https://example.invalid/disk.img, sha256: %s } }
  resources: { cpu: 1, memory: 512Mi }
  disk: { size: 1Gi }
`, ns, digest))
	t.Cleanup(func() { _, _ = c.kvo("", "delete", "silo", "crafted", "-n", ns, "--wait=false") })
	c.eventually("a disk image that names a backing file is refused", 10*time.Minute, func() (bool, string) {
		d, code := c.kvo("", "describe", "silo", "crafted", "-n", ns)
		return code == 0 && !strings.Contains(d, "Phase:      Running") && strings.Contains(d, "backing file"), d
	})
	if mode := strings.TrimSpace(c.mustSh("stat -c %a " + path)); mode != "600" {
		t.Fatalf("image mode %s", mode)
	}
}

func craftedQcow2() []byte {
	b := make([]byte, 104)
	copy(b[0:4], "QFI\xfb")
	binary.BigEndian.PutUint32(b[4:], 3)
	binary.BigEndian.PutUint64(b[8:], 104)
	binary.BigEndian.PutUint32(b[16:], 11)
	binary.BigEndian.PutUint32(b[20:], 16)
	binary.BigEndian.PutUint64(b[24:], 1<<20)
	binary.BigEndian.PutUint32(b[100:], 104)
	return append(b, []byte("backing.img")...)
}
