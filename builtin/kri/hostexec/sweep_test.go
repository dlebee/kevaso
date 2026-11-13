package hostexec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"kevaso.com/core/sdk/kri"
)

func TestParseStat(t *testing.T) {
	state, ppid, sid, ok := parseStat([]byte("4300 (a) b (c)) S 50 4300 4299 0 -1 4194560"))
	if !ok || state != "S" || ppid != 50 || sid != 4299 {
		t.Fatalf("%s %d %d %v", state, ppid, sid, ok)
	}
}

func TestMembers(t *testing.T) {
	procs := map[int]Proc{
		10: {PID: 10, PPID: 5, SID: 10},               // the exec's root, environment cleared
		11: {PID: 11, PPID: 10, SID: 10},              // its child
		12: {PID: 12, PPID: 2, SID: 10},               // reparented, same session
		13: {PID: 13, PPID: 12, SID: 13},              // a child of that one, in a session of its own
		20: {PID: 20, PPID: 2, SID: 20, Marked: true}, // a daemon that kept the marker
		21: {PID: 21, PPID: 20, SID: 20},
		30: {PID: 30, PPID: 2, SID: 30},  // someone else's
		31: {PID: 31, PPID: 30, SID: 10}, // someone else's child, but in the exec's session
	}
	if got := Members(procs, []int{10}); !slices.Equal(got, []int{10, 11, 12, 13, 20, 21, 31}) {
		t.Fatalf("members %v", got)
	}
	delete(procs, 10) // the root exited: its session is still the exec's
	if got := Members(procs, []int{10}); !slices.Equal(got, []int{11, 12, 13, 20, 21, 31}) {
		t.Fatalf("members %v", got)
	}
	if got := Members(procs, nil); !slices.Equal(got, []int{20, 21}) { // no root known: what's marked
		t.Fatalf("members %v", got)
	}
}

// fakeProcs is a /proc for Sweep, where a process may fork once more before it's stopped.
type fakeProcs struct {
	mu    sync.Mutex
	procs map[int]Proc
	env   map[int]string
	forks map[int]int // pid → the child it forks just before its SIGSTOP lands
	sigs  []string
}

func (f *fakeProcs) Run(_ context.Context, c Cmd) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sigs = append(f.sigs, c.Name+" "+strings.Join(c.Args, " "))
	if c.Name == "kill" && c.Args[0] == "-STOP" {
		for _, a := range c.Args[1:] {
			p, _ := strconv.Atoi(a)
			if child, ok := f.forks[p]; ok {
				f.procs[child] = Proc{PID: child, PPID: p, SID: child} // setsid'd, environment cleared
				delete(f.forks, p)
			}
		}
	}
	return 0, nil
}
func (f *fakeProcs) WriteFile(string, []byte, os.FileMode) error { return nil }
func (f *fakeProcs) RemoveAll(string) error                      { return nil }
func (f *fakeProcs) ReadFile(p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pid, _ := strconv.Atoi(strings.Split(p, "/")[2])
	pr, ok := f.procs[pid]
	if !ok {
		return nil, os.ErrNotExist
	}
	switch filepath.Base(p) {
	case "stat":
		return fmt.Appendf(nil, "%d (x) S %d %d %d", pid, pr.PPID, pr.SID, pr.SID), nil
	case "environ":
		return []byte(f.env[pid]), nil
	}
	return nil, nil
}
func (f *fakeProcs) Glob(string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for p := range f.procs {
		out = append(out, fmt.Sprintf("/proc/%d/stat", p))
	}
	return out, nil
}

// A process forks between the scan that found it and its SIGSTOP: the next round finds the child
// (its parent is a member), stops it, and only then is everything killed.
func TestSweepStopsWhatForksDuringIt(t *testing.T) {
	f := &fakeProcs{
		procs: map[int]Proc{40: {PID: 40, PPID: 2, SID: 40}, 41: {PID: 41, PPID: 40, SID: 40}, 50: {PID: 50, PPID: 2, SID: 50}},
		env:   map[int]string{40: kri.ExecMarkerEnv + "=m\x00"},
		forks: map[int]int{41: 42},
	}
	if n := Sweep(context.Background(), f, "m", nil); n != 3 {
		t.Fatalf("swept %d, want 3 (%v)", n, f.sigs)
	}
	want := []string{"kill -STOP 40 41", "kill -STOP 42", "kill -KILL 40 41 42"}
	if !slices.Equal(f.sigs, want) {
		t.Fatalf("signals %q, want %q", f.sigs, want)
	}
}

func TestSweepWithNothingToFindSendsNothing(t *testing.T) {
	f := &fakeProcs{procs: map[int]Proc{50: {PID: 50, PPID: 2, SID: 50}}}
	if n := Sweep(context.Background(), f, "m", []int{999}); n != 0 || len(f.sigs) != 0 {
		t.Fatalf("swept %d: %v", n, f.sigs)
	}
}

// On Linux, for real: an exec whose command cleared its environment (env -i) and left a child
// in the background. The VM's form: the marker on the command line of a shell that stays; the
// OpenShell form: Held, with no session of its own; the container's form: the root known, nothing
// marked. Both the Go sweep and SweepScript.
func TestSweepOnLinux(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc here")
	}
	type tc struct {
		name   string
		setsid bool // as runc and sshd do
		start  func(marker string) *exec.Cmd
		sweep  func(t *testing.T, marker string, root int) error
	}
	vmStyle := func(m string) *exec.Cmd {
		return exec.Command("sh", "-c", ": "+kri.ExecMarkerEnv+"="+m+" ; env -i sh -c 'sleep 30 & sleep 30' ; exit $?")
	}
	held := func(m string) *exec.Cmd {
		a := Held(m, []string{"env", "-i", "sh", "-c", "sleep 30 & sleep 30"})
		return exec.Command(a[0], a[1:]...)
	}
	containerStyle := func(string) *exec.Cmd {
		return exec.Command("env", "-i", "sh", "-c", "sleep 30 & sleep 30")
	}
	goSweep := func(t *testing.T, m string, root int) error {
		if _, err := exec.LookPath("kill"); err != nil {
			t.Skip("no kill command here (procps): the host sweep runs it")
		}
		var roots []int
		if root > 0 {
			roots = []int{root}
		}
		if Sweep(context.Background(), Local{}, m, roots) == 0 {
			return fmt.Errorf("found nothing")
		}
		return nil
	}
	script := func(_ *testing.T, m string, _ int) error {
		out, err := exec.Command("sh", "-c", SweepScript, "sh", m).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v %s", err, out)
		}
		return nil
	}
	for _, c := range []tc{
		{"vm/go", true, vmStyle, goSweep},
		{"vm/script", true, vmStyle, script},
		{"held/script", false, held, script},
		{"container/go", true, containerStyle, goSweep},
	} {
		t.Run(c.name, func(t *testing.T) {
			marker := NewMarker()
			cmd := c.start(marker)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: c.setsid}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			other := exec.Command("sleep", "30")
			other.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if err := other.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
			root := cmd.Process.Pid
			tree := func() []int { // the command and everything below it
				procs := Snapshot(Local{}, "")
				in := map[int]bool{root: true}
				for grew := true; grew; {
					grew = false
					for pid, p := range procs {
						if !in[pid] && in[p.PPID] {
							in[pid], grew = true, true
						}
					}
				}
				var out []int
				for pid := range in {
					if _, alive := procs[pid]; alive {
						out = append(out, pid)
					}
				}
				return out
			}
			sleeping := func(pids []int) int { // both sleeps started (some shells exec the last command)
				n := 0
				for _, pid := range pids {
					if b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); string(b) == "sleep\x0030\x00" {
						n++
					}
				}
				return n
			}
			var ours []int
			for deadline := time.Now().Add(5 * time.Second); sleeping(ours) < 2; ours = tree() {
				if time.Now().After(deadline) {
					t.Fatalf("the command never got going: %v", ours)
				}
				time.Sleep(10 * time.Millisecond) // waiting for processes to exist, not for a race to settle
			}
			r := 0
			if c.name == "container/go" {
				r = root
			}
			if err := c.sweep(t, marker, r); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			alive := func() []int {
				procs := Snapshot(Local{}, "")
				var out []int
				for _, pid := range ours {
					if _, ok := procs[pid]; ok {
						out = append(out, pid)
					}
				}
				return out
			}
			for deadline := time.Now().Add(5 * time.Second); len(alive()) > 0; {
				if time.Now().After(deadline) {
					t.Fatalf("still running after the sweep: %v of %v", alive(), ours)
				}
				time.Sleep(10 * time.Millisecond) // the kernel reaping the killed processes
			}
			if err := other.Process.Signal(syscall.Signal(0)); err != nil {
				t.Fatal("the sweep killed an unrelated process")
			}
		})
	}
}

// What a sweep still can't find, said here so it isn't mistaken for covered: a process that left
// the exec's tree (its parent exited) and its session (setsid), and has no marker (env -i). A
// container exec that ends before the host sees its first process start, with its environment
// already cleared, also leaves no root to start from (Exec looks once more when the CLI returns).
func TestMembersMissADaemonThatLeftEverything(t *testing.T) {
	procs := map[int]Proc{
		10: {PID: 10, PPID: 5, SID: 10},
		60: {PID: 60, PPID: 1, SID: 60}, // was 10's grandchild: forked, setsid, parent exited, env -i
	}
	if got := Members(procs, []int{10}); !slices.Equal(got, []int{10}) {
		t.Fatalf("members %v", got)
	}
}
