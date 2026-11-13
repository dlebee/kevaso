package keep

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
)

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func sh(t *testing.T, argv []string) string {
	t.Helper()
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v: %s", argv, err, out)
	}
	return string(out)
}

// The real scripts, in a real shell: start detached, probe, see it end with its code, stop. The
// daemon's script has quotes and $ in it, which must reach it untouched.
func TestScriptsInAShell(t *testing.T) {
	Dir = t.TempDir()
	d := v1.Daemon{Name: "worker", Run: `echo "it's $((1+1))"; sleep 0.3; exit 3`}
	start := time.Now()
	sh(t, StartCommand(d))
	if time.Since(start) > 2*time.Second {
		t.Fatal("start waited for the daemon")
	}
	if p := ParseProbe(sh(t, ProbeCommand(d))); !p.Running {
		t.Fatalf("just started: %+v", p)
	}
	deadline := time.Now().Add(5 * time.Second)
	var p Probe
	for time.Now().Before(deadline) {
		if p = ParseProbe(sh(t, ProbeCommand(d))); !p.Running {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if p.Running || p.Absent || p.Exit != 3 {
		t.Fatalf("after it ended: %+v", p)
	}
	if log := sh(t, []string{"cat", Dir + "/worker.log"}); !strings.Contains(log, "it's 2") {
		t.Fatalf("log %q", log)
	}
	if p := ParseProbe(sh(t, ProbeCommand(v1.Daemon{Name: "never"}))); !p.Absent {
		t.Fatalf("unknown daemon: %+v", p)
	}
	// Stop: a long one is killed with its children.
	long := v1.Daemon{Name: "long", Run: "sleep 30"}
	sh(t, StartCommand(long))
	sh(t, StopCommand("long"))
	if p := ParseProbe(sh(t, ProbeCommand(long))); !p.Absent {
		t.Fatalf("after stop: %+v", p)
	}
	// Upkeep: check fails, fix fixes, check passes.
	flag := Dir + "/ok"
	u := v1.Upkeep{Name: "x", Every: "1h", Check: "test -f " + flag, Fix: "touch " + flag}
	if err := exec.Command("sh", "-c", CheckCommand(u)[2]).Run(); err == nil {
		t.Fatal("check passed before the fix")
	}
	sh(t, FixCommand(u))
	sh(t, CheckCommand(u))
}

func TestAsUserWraps(t *testing.T) {
	got := StartCommand(v1.Daemon{Name: "c", Run: "claude remote-control", User: "dev"})[2]
	if !strings.Contains(got, "su -s /bin/sh ") || !strings.Contains(got, "'dev'") {
		t.Fatalf("as dev: %s", got)
	}
}

func TestParseProbe(t *testing.T) {
	for out, want := range map[string]Probe{
		"running\n": {Running: true}, "exited 0\n": {Exit: 0}, "exited 137": {Exit: 137},
		"exited x": {Exit: -1}, "absent\n": {Absent: true}, "": {Absent: true},
	} {
		if got := ParseProbe(out); got != want {
			t.Errorf("ParseProbe(%q) = %+v, want %+v", out, got, want)
		}
	}
}

func TestBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{0: 10 * time.Second, 1: 20 * time.Second, 3: 80 * time.Second, 10: 5 * time.Minute} {
		if got := Backoff(n); got != want {
			t.Errorf("Backoff(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestDecideDaemon(t *testing.T) {
	d := v1.Daemon{Name: "claude"}
	// New: start it.
	st, start, _ := DecideDaemon(d, v1.DaemonStatus{}, Probe{Absent: true}, t0)
	if !start || st.State != v1.DaemonRunning || st.Restarts != 0 {
		t.Fatalf("new: %+v %v", st, start)
	}
	// Running: nothing to do.
	if _, start, again := DecideDaemon(d, st, Probe{Running: true}, t0.Add(time.Minute)); start || again != ProbeEvery {
		t.Fatal("running daemon restarted")
	}
	// Dies after 30s: recorded, restarted after the first backoff.
	st, start, again := DecideDaemon(d, st, Probe{Exit: 1}, t0.Add(30*time.Second))
	if start || st.State != v1.DaemonWaiting || *st.ExitCode != 1 || again != 10*time.Second {
		t.Fatalf("died: %+v %v %v", st, start, again)
	}
	st, start, _ = DecideDaemon(d, st, Probe{Exit: 1}, t0.Add(40*time.Second))
	if !start || st.Restarts != 1 || st.State != v1.DaemonRunning {
		t.Fatalf("restart: %+v %v", st, start)
	}
	// Dies again quickly: longer backoff.
	st, _, again = DecideDaemon(d, st, Probe{Exit: 1}, t0.Add(45*time.Second))
	if again != 20*time.Second {
		t.Fatalf("second backoff %v", again)
	}
	// One that ran for a long time before dying gets no penalty.
	long := v1.DaemonStatus{Name: "claude", State: v1.DaemonRunning, Restarts: 6, StartedAt: &t0}
	st, _, again = DecideDaemon(d, long, Probe{Exit: 0}, t0.Add(time.Hour))
	if st.Restarts != 0 || again != 10*time.Second {
		t.Fatalf("stable then died: %+v %v", st, again)
	}
	// Policies.
	if st, start, _ := DecideDaemon(v1.Daemon{Name: "x", Restart: v1.RestartNever}, v1.DaemonStatus{State: v1.DaemonRunning}, Probe{Exit: 1}, t0); start || st.State != v1.DaemonExited {
		t.Fatalf("never: %+v", st)
	}
	if st, _, _ := DecideDaemon(v1.Daemon{Name: "x", Restart: v1.RestartOnFailure}, v1.DaemonStatus{State: v1.DaemonRunning}, Probe{Exit: 0}, t0); st.State != v1.DaemonExited {
		t.Fatalf("onFailure, clean exit: %+v", st)
	}
	if st, _, _ := DecideDaemon(v1.Daemon{Name: "x", Restart: v1.RestartOnFailure}, v1.DaemonStatus{State: v1.DaemonRunning}, Probe{Exit: 2}, t0); st.State != v1.DaemonWaiting {
		t.Fatalf("onFailure, failed: %+v", st)
	}
}

func TestUpkeep(t *testing.T) {
	u := v1.Upkeep{Name: "claude up to date", Every: "6h"}
	if due, _ := Due(u, v1.UpkeepStatus{}, t0); !due {
		t.Fatal("never checked: due")
	}
	last := t0
	if due, again := Due(u, v1.UpkeepStatus{LastCheck: &last}, t0.Add(time.Hour)); due || again != 5*time.Hour {
		t.Fatalf("an hour later: %v %v", due, again)
	}
	if due, _ := Due(u, v1.UpkeepStatus{LastCheck: &last}, t0.Add(6*time.Hour)); !due {
		t.Fatal("6h later: due")
	}
	for o, want := range map[Outcome]string{
		{Check: 0}:                                            v1.UpkeepOK,
		{Check: 1, FixRan: true}:                              v1.UpkeepFixed,
		{Check: 1, FixRan: true, Fix: 1}:                      v1.UpkeepFailed,
		{Check: 1, FixRan: true, After: 1}:                    v1.UpkeepFailed,
		{Check: 1, FixRan: true, Fix: 2, Output: "npm: E404"}: v1.UpkeepFailed,
	} {
		if st := Result(u, v1.UpkeepStatus{}, o, t0); st.State != want || st.Message != o.Output {
			t.Errorf("%+v → %+v, want %s", o, st, want)
		}
	}
	if got := Degraded([]v1.UpkeepStatus{{Name: "a", State: v1.UpkeepOK}, {Name: "b", State: v1.UpkeepFailed}}); len(got) != 1 || got[0] != "b" {
		t.Fatalf("Degraded = %v", got)
	}
}

// shells are the sh implementations silos have: dash (Debian, Ubuntu), bash, busybox (Alpine).
func shells(t *testing.T) []string {
	var out []string
	for _, s := range []string{"dash", "bash", "busybox"} {
		if p, err := exec.LookPath(s); err == nil {
			if s == "busybox" {
				p += " sh"
			}
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		t.Skip("no dash, bash or busybox here")
	}
	return out
}

// in runs one of the commands with a given sh in place of "sh".
func in(t *testing.T, shell string, argv []string) string {
	t.Helper()
	return sh(t, append(strings.Fields(shell), argv[1:]...))
}

// A stop takes the daemon's whole process group in every shell: dash's kill doesn't take
// "kill -TERM -- -PGID" (Illegal number), which left the daemon running with only its wrapper gone.
func TestStopKillsTheGroupInEveryShell(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("no setsid here: a stop only takes the wrapper")
	}
	for _, shell := range shells(t) {
		t.Run(filepath.Base(shell), func(t *testing.T) {
			Dir = t.TempDir()
			d := v1.Daemon{Name: "long", Run: "sleep 30 & echo $! > " + Dir + "/child; wait"}
			in(t, shell, StartCommand(d))
			var child string
			for i := 0; i < 100 && child == ""; i++ {
				time.Sleep(20 * time.Millisecond)
				child = strings.TrimSpace(sh(t, []string{"sh", "-c", "cat " + Dir + "/child 2>/dev/null || true"}))
			}
			if child == "" {
				t.Fatal("the daemon never started")
			}
			in(t, shell, StopCommand("long"))
			for i := 0; i < 100; i++ {
				if exec.Command("kill", "-0", child).Run() != nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			_ = exec.Command("kill", "-9", child).Run()
			t.Fatalf("with %s, the daemon's child %s outlived the stop", shell, child)
		})
	}
}

// A daemon whose wrapper was killed and never reaped is a zombie (in a container whose PID 1 is
// "sleep infinity", it stays one): kill -0 still succeeds on it, but it isn't running.
func TestProbeSeesAZombieAsDead(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("no /proc here")
	}
	Dir = t.TempDir()
	pid, _, _ := files("z")
	// The child exits at once; its parent becomes "sleep 3", which never reaps it.
	parent := exec.Command("sh", "-c", "sh -c 'exit 0' & echo $! > "+pid+"; exec sleep 3")
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Process.Kill(); _ = parent.Wait() }()
	zombie := false
	for i := 0; i < 100 && !zombie; i++ {
		time.Sleep(20 * time.Millisecond)
		b, err := os.ReadFile(pid)
		if err != nil || len(b) == 0 {
			continue
		}
		st, _ := os.ReadFile("/proc/" + strings.TrimSpace(string(b)) + "/status")
		zombie = strings.Contains(string(st), "State:\tZ")
	}
	if !zombie {
		t.Fatal("couldn't make a zombie")
	}
	for _, shell := range shells(t) {
		if p := ParseProbe(in(t, shell, ProbeCommand(v1.Daemon{Name: "z"}))); p.Running || p.Absent || p.Exit != -1 {
			t.Errorf("%s: a zombie probed as %+v, want exited -1", filepath.Base(shell), p)
		}
	}
}

// When the fix last ran is kept: the next check that passes on its own doesn't forget it.
func TestUpkeepKeepsLastFix(t *testing.T) {
	u := v1.Upkeep{Name: "marker", Every: "1m"}
	fixed := Result(u, v1.UpkeepStatus{}, Outcome{Check: 1, FixRan: true}, t0)
	if fixed.State != v1.UpkeepFixed || fixed.LastFix == nil || !fixed.LastFix.Equal(t0) {
		t.Fatalf("fixed: %+v", fixed)
	}
	later := t0.Add(time.Minute)
	ok := Result(u, fixed, Outcome{Check: 0}, later)
	if ok.State != v1.UpkeepOK || !ok.LastCheck.Equal(later) || ok.LastFix == nil || !ok.LastFix.Equal(t0) {
		t.Fatalf("a passing check after a fix: %+v, want LastFix %s kept", ok, t0)
	}
	failed := Result(u, ok, Outcome{Check: 1, FixRan: true, Fix: 1, Output: "no"}, later.Add(time.Minute))
	if failed.LastFix == nil || !failed.LastFix.Equal(later.Add(time.Minute)) {
		t.Fatalf("a fix that ran and failed: %+v", failed)
	}
}
