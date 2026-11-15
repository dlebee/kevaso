package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// K-094: a VM whose state file can't be read (a power cut mid-write) is never taken for absent: a
// fence would count it stopped. Kill still kills its VMM, by the unit's name, and Status says
// whether it runs, never "not here".
func TestAnUnreadableStateIsNotAnAbsentVM(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	killed := false
	h.answer = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "systemctl kill --signal=SIGKILL") && strings.HasSuffix(cmd, n.Unit) {
			killed = true
		}
		if cmd == "systemctl is-active "+n.Unit && !killed {
			return "active", nil
		}
		if strings.HasPrefix(cmd, "systemctl is-active") {
			return "inactive", errors.New("exit 3")
		}
		return "", nil
	}
	h.files[n.Dir+"/silo.json"] = []byte(`{"id": `)
	if st, err := r.Status(ctx, sp.ID); err == nil && st.State != kri.Running {
		t.Fatalf("its VMM runs, its state is unreadable: Status %s", st.State)
	}
	if err := kri.Kill(ctx, r, sp.ID); errors.Is(err, kri.ErrNotFound) || !killed {
		t.Fatalf("Kill: %v (VMM killed: %v): a fence would count it stopped", err, killed)
	}
	st, err := r.Status(ctx, sp.ID)
	if err != nil || st.State == kri.Absent || st.State == kri.Running {
		t.Fatalf("after the kill: %s %v: neither absent nor running, it is there and stopped", st.State, err)
	}
}
