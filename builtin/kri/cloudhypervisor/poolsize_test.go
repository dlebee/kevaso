package cloudhypervisor

import (
	"errors"
	"strings"
	"testing"
)

// §0.8: a local volume beyond the host's storage is refused at creation, with the numbers. The
// host's side is the size of its thin pool and how much its thin volumes already promise.
func TestPoolSizeAndWhatIsProvisioned(t *testing.T) {
	h := newFakeHost()
	h.answer = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "lvs ") {
			return "  silos 107374182400 \n" + // the pool: 100 GiB
				"  kv-dev-web-disk 21474836480 silos\n" + // 20 GiB
				"  kv-dev-db-data 53687091200 silos\n" + // 50 GiB
				"  root 10737418240 \n", nil // not in the pool
		}
		return "", nil
	}
	r := &Runtime{Host: h}
	size, provisioned, err := r.PoolSize(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if size != 100<<30 || provisioned != 70<<30 {
		t.Fatalf("pool %d, provisioned %d: want %d and %d", size, provisioned, int64(100<<30), int64(70<<30))
	}
	h.answer = func(cmd string) (string, error) { return "  root 10737418240 \n", nil }
	if _, _, err := r.PoolSize(t.Context()); err == nil {
		t.Error("no pool, and no error")
	}
}

// §0.8: a local volume beyond what the host's pool has left is refused at creation, with the
// numbers, and nothing is made. One that fits is made (a thin pool is never promised more than
// its size, so running out inside a volume is the silo's own problem, not the host's).
func TestALocalVolumeBeyondThePoolIsRefusedWithTheNumbers(t *testing.T) {
	h := newFakeHost()
	h.answer = func(cmd string) (string, error) {
		switch {
		case strings.HasPrefix(cmd, "lvs --noheadings --units b"):
			return "  silos 107374182400 \n  kv-other 75161927680 silos\n", nil // 100 GiB, 70 GiB promised
		case strings.HasPrefix(cmd, "lvs --noheadings kevaso/"):
			return "", errors.New("not found")
		}
		return "", nil
	}
	r := &Runtime{Host: h}
	st := State{ID: id("web")}
	err := r.applyLayout(t.Context(), st, Layout{}, Layout{Disks: []VolumeDisk{{Name: "data", LV: "kv-web-data", SizeBytes: 40 << 30}}})
	if err == nil || !strings.Contains(err.Error(), "volume data needs 40Gi") || !strings.Contains(err.Error(), "100Gi") || !strings.Contains(err.Error(), "30Gi left") {
		t.Fatalf("refusal: %v", err)
	}
	if has(h.commands(), "lvcreate") {
		t.Fatalf("made it anyway: %v", h.commands())
	}
	_ = r.applyLayout(t.Context(), st, Layout{}, Layout{Disks: []VolumeDisk{{Name: "data", LV: "kv-web-data", SizeBytes: 20 << 30}}})
	if !has(h.commands(), "lvcreate -q -T kevaso/silos -V 20480m -n kv-web-data") {
		t.Fatalf("a volume that fits wasn't made: %v", h.commands())
	}
}
