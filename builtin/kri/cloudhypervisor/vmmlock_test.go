package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// review-batch4 claim 3. (a) A failed or inactive unit still showing an old MainPID whose number
// is now an unrelated process's was Running for as long as that process lived. (b) A VMM with
// MainPID 0, no cgroup.procs and a command line pgrep doesn't match was Stopped, and the next
// Start launched a second VMM on its disk. The MainPID counts only for a process that may be the
// VMM; the VMM's lock on its silo (held by the VMM itself) counts whatever else says; the unit
// starts the VMM under that lock.

func vmmHost(t *testing.T, state, mainPID string, locked bool) (*fakeHost, *Runtime, kri.ID) {
	t.Helper()
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	h.answer = func(cmd string) (string, error) {
		switch {
		case cmd == "systemctl is-active "+n.Unit:
			return state, errors.New("exit 3")
		case strings.HasPrefix(cmd, "systemctl show") && strings.HasSuffix(cmd, n.Unit):
			return "MainPID=" + mainPID + "\nControlGroup=/system.slice/" + n.Unit, nil // no cgroup.procs there
		case strings.HasPrefix(cmd, "flock ") && strings.Contains(cmd, n.Dir+"/vmm.lock") && locked:
			return "", errors.New("exit status 75")
		}
		return "", nil // pgrep: nothing
	}
	return h, r, sp.ID
}

func TestAReusedMainPIDIsNotTheVMM(t *testing.T) {
	for _, state := range []string{"failed", "inactive"} {
		t.Run(state, func(t *testing.T) {
			h, r, id := vmmHost(t, state, "4242", false)
			h.files["/proc/4242/cmdline"] = []byte("sleep\x00100\x00") // the number, reused
			if st, err := r.Status(context.Background(), id); err != nil || st.State == kri.Running {
				t.Fatalf("Status %s %v: an unrelated process with the unit's old MainPID counts as its VMM", st.State, err)
			}
			n := NamesFor(id)
			h.files["/proc/4242/cmdline"] = []byte("/usr/local/bin/cloud-hypervisor\x00--api-socket\x00" + n.Socket + "\x00--cpus\x00boot=2\x00")
			if st, err := r.Status(context.Background(), id); err != nil || st.State != kri.Running {
				t.Fatalf("Status %s %v: the VMM itself, under the unit's MainPID, isn't running", st.State, err)
			}
		})
	}
}

func TestAVMMHoldingItsLockRunsWhateverElseSays(t *testing.T) {
	_, r, id := vmmHost(t, "inactive", "0", true)
	if err := r.Kill(context.Background(), id); err == nil {
		t.Fatal("Kill said done while a VMM holds the silo's lock")
	}
	if st, err := r.Status(context.Background(), id); err != nil || st.State != kri.Running {
		t.Fatalf("Status %s %v while a VMM holds the silo's lock: the next Start would launch a second one on its disk", st.State, err)
	}
}

func TestTheVMMRunsUnderItsSilosLock(t *testing.T) {
	h, _, id := vmmHost(t, "inactive", "0", false)
	n := NamesFor(id)
	unit := string(h.files["/etc/systemd/system/"+n.Unit])
	want := "ExecStart=/usr/bin/flock --no-fork -w 5 -E 75 " + n.Dir + "/vmm.lock" + " " + BinDir + "/cloud-hypervisor --api-socket " + n.Socket + " "
	if !strings.Contains(unit, want) {
		t.Fatalf("the VMM isn't started under its lock (want %q):\n%s", want, unit)
	}
}
