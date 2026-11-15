package cloudhypervisor

import (
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
