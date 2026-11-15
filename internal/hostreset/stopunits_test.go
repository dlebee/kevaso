package hostreset

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSystemctl answers as the real one does for the units it has (have: unit → is-active) and
// for a unit it doesn't: is-active "inactive" (exit 3), LoadState not-found, and a disable or
// enable naming it refuses the whole command, doing nothing for the others either ("Unit file X
// does not exist"). fail names units whose stop fails. What it did goes to log.
func fakeSystemctl(t *testing.T, have map[string]string, fail string) (bin, log string) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	bin, log = t.TempDir(), filepath.Join(t.TempDir(), "did")
	var known []string
	var states []string
	for u, st := range have {
		known = append(known, u)
		states = append(states, u+") echo "+st+"; [ "+st+" = active ];;")
	}
	script := `#!` + sh + `
known=" ` + strings.Join(known, " ") + ` "
has() { case "$known" in *" $1 "*) return 0;; esac; return 1; }
verb=$1; shift
case "$verb" in
show) for u in "$@"; do :; done; if has "$u"; then echo loaded; else echo not-found; fi;;
is-active) case "$1" in ` + strings.Join(states, " ") + ` *) echo inactive; exit 3;; esac;;
disable|enable)
  for a in "$@"; do case "$a" in --*) ;; *) has "$a" || { echo "Failed to $verb unit: Unit file $a does not exist." >&2; exit 1; };; esac; done
  echo "$verb $*" >> ` + log + `;;
stop)
  for a in "$@"; do case " ` + fail + ` " in *" $a "*) echo "Job for $a failed." >&2; exit 1;; esac; done
  echo "stop $*" >> ` + log + `;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

func runScript(t *testing.T, bin, script string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// From the Linodes (linode-3.md, core finding 5): on a system node that isn't a worker there is no
// kevaso-fence unit, `systemctl disable --now kevasod.service kevaso-fence.service` refused both
// and stopped nothing, and the stop step's `; true` hid it: kvoadm reset then refused, kevasod
// still running. Each unit is stopped by itself, only those the host has, and a failing stop
// fails the step, naming the unit.
func TestTheResetStopsKevasodOnANodeWithoutAFence(t *testing.T) {
	stop := Plan(PlanInput{})[0]
	if stop.Name != StopStep {
		t.Fatalf("the plan's first step is %q", stop.Name)
	}
	t.Run("a control-plane-only node", func(t *testing.T) {
		bin, log := fakeSystemctl(t, map[string]string{"kevasod.service": "active"}, "")
		if out, err := runScript(t, bin, stop.Script); err != nil {
			t.Fatalf("the stop step failed: %v %s", err, out)
		}
		did, _ := os.ReadFile(log)
		if !strings.Contains(string(did), "stop kevasod.service") {
			t.Fatalf("kevasod wasn't stopped: %q", did)
		}
	})
	t.Run("a stop that fails", func(t *testing.T) {
		bin, _ := fakeSystemctl(t, map[string]string{"kevasod.service": "active", "kevaso-fence.service": "active"}, "kevasod.service")
		out, err := runScript(t, bin, stop.Script)
		if err == nil || !strings.Contains(out, "stopping kevasod.service failed") {
			t.Fatalf("a failing stop was hidden: %v %q", err, out)
		}
	})
	t.Run("started again on that node", func(t *testing.T) {
		bin, log := fakeSystemctl(t, map[string]string{"kevasod.service": "inactive"}, "")
		if out, err := runScript(t, bin, StartAgainScript); err != nil {
			t.Fatalf("starting kevasod again failed: %v %s", err, out)
		}
		did, _ := os.ReadFile(log)
		if !strings.Contains(string(did), "enable --now kevasod.service") {
			t.Fatalf("kevasod wasn't started again: %q", did)
		}
	})
}
