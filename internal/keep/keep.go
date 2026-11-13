// Package keep decides daemons and upkeep inside a silo (design §0.5). Pure: it builds the
// commands the host's agent runs through the runtime's exec (nothing of Kevaso's is installed in
// the silo), reads what they print, and decides what's next.
//
// A daemon is started detached, under a small shell wrapper that records its pid and, when it
// ends, its exit code, in /run/kevaso/daemons. The agent probes those files and restarts a dead
// daemon per its policy, with a backoff that grows while it keeps dying. Upkeep runs its check
// every period; only a failing check runs the fix, then the check again.
package keep

import (
	"strconv"
	"strings"
	"time"

	v1 "kevaso.com/core/api/v1"
)

// Dir is where daemon files live inside the silo (tmpfs in a VM: gone on reboot, as it should).
// A variable only so tests can run the real scripts in a temporary folder.
var Dir = "/run/kevaso/daemons"

// quote makes s one single-quoted shell word.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func shellOf(s string) string {
	if s == "" {
		return "sh"
	}
	return s
}

// as runs script with shell, as user ("" or root: as root).
func as(user, shell, script string) string {
	cmd := shellOf(shell) + " -c " + quote(script)
	if user == "" || user == "root" {
		return cmd
	}
	return "su -s /bin/sh " + quote(user) + " -c " + quote(cmd)
}

func files(name string) (pid, exit, log string) {
	base := Dir + "/" + name
	return base + ".pid", base + ".exit", base + ".log"
}

// StartCommand starts a daemon detached and returns at once.
func StartCommand(d v1.Daemon) []string {
	pid, exit, log := files(d.Name)
	wrapper := as(d.User, d.Shell, d.Run) + "; echo $? > " + exit
	// setsid makes it a process group of its own, so a stop takes its children too (images
	// without setsid still work; only a stop is less thorough).
	script := "mkdir -p " + Dir + " && rm -f " + exit + " && cd / && S=$(command -v setsid || true) && " +
		"($S sh -c " + quote(wrapper) + " >>" + log + " 2>&1 </dev/null & echo $! > " + pid + ")"
	return []string{"sh", "-c", script}
}

// ProbeCommand prints running, exited CODE, or absent. A zombie isn't running: a killed wrapper
// stays one where nothing reaps it (a container whose PID 1 is "sleep infinity"), and kill -0
// still succeeds on it, so with /proc the process's state is read instead.
func ProbeCommand(d v1.Daemon) []string {
	pid, exit, _ := files(d.Name)
	alive := "a=no; p=$(cat " + pid + " 2>/dev/null); if [ -n \"$p\" ]; then " +
		"if [ -r /proc/$p/status ]; then s=; while read -r k v _; do if [ \"$k\" = State: ]; then s=$v; break; fi; done < /proc/$p/status 2>/dev/null; " +
		"case $s in Z|X|'') ;; *) a=yes ;; esac; " +
		"elif [ ! -d /proc/self ] && kill -0 \"$p\" 2>/dev/null; then a=yes; fi; fi; "
	script := alive + "if [ $a = yes ]; then echo running; " +
		"elif [ -f " + exit + " ]; then echo \"exited $(cat " + exit + ")\"; " +
		"elif [ -f " + pid + " ]; then echo exited -1; else echo absent; fi"
	return []string{"sh", "-c", script}
}

// StopCommand stops a daemon that's no longer in the spec (its whole process group). The signal
// is given with -s: dash's kill reads "kill -TERM -- -PGID" as a bad number.
func StopCommand(name string) []string {
	pid, exit, _ := files(name)
	return []string{"sh", "-c", "if [ -f " + pid + " ]; then p=$(cat " + pid + "); kill -s TERM -- -\"$p\" 2>/dev/null || kill -s TERM \"$p\" 2>/dev/null; fi; rm -f " + pid + " " + exit + "; true"}
}

// Probe is what ProbeCommand said.
type Probe struct {
	Running bool
	Absent  bool // never started here (a new silo, or after a reboot)
	Exit    int  // exited: its code (-1: unknown, killed with the wrapper)
}

// ParseProbe reads ProbeCommand's output.
func ParseProbe(out string) Probe {
	f := strings.Fields(out)
	switch {
	case len(f) == 1 && f[0] == "running":
		return Probe{Running: true}
	case len(f) == 2 && f[0] == "exited":
		code, err := strconv.Atoi(f[1])
		if err != nil {
			code = -1
		}
		return Probe{Exit: code}
	}
	return Probe{Absent: true}
}

// Backoff is the wait before restart number n+1: 10s, 20s, 40s, … at most 5m.
func Backoff(restarts int) time.Duration {
	d := 10 * time.Second
	for i := 0; i < restarts && d < 5*time.Minute; i++ {
		d *= 2
	}
	return min(d, 5*time.Minute)
}

// StableAfter: a daemon that ran this long before dying restarts without the backoff it had.
const StableAfter = 10 * time.Minute

// ProbeEvery is how often running daemons are looked at.
const ProbeEvery = 15 * time.Second

// DecideDaemon is what to do with one daemon: its next status, whether to start it now, and when
// to look again.
func DecideDaemon(d v1.Daemon, st v1.DaemonStatus, p Probe, now time.Time) (v1.DaemonStatus, bool, time.Duration) {
	st.Name = d.Name
	if p.Running {
		st.State, st.NextStart = v1.DaemonRunning, nil
		if st.StartedAt == nil {
			t := now
			st.StartedAt = &t
		}
		return st, false, ProbeEvery
	}
	if p.Absent {
		t := now
		st.State, st.StartedAt, st.NextStart, st.ExitCode = v1.DaemonRunning, &t, nil, nil
		return st, true, ProbeEvery
	}
	// It ended.
	code := p.Exit
	if st.State == v1.DaemonRunning { // just found dead: record it once
		st.ExitCode = &code
		if st.StartedAt != nil && now.Sub(*st.StartedAt) >= StableAfter {
			st.Restarts = 0 // it had been fine for a while: no penalty
		}
	}
	restart := d.Restart
	if restart == "" {
		restart = v1.RestartAlways
	}
	if restart == v1.RestartNever || (restart == v1.RestartOnFailure && code == 0) {
		st.State, st.NextStart = v1.DaemonExited, nil
		return st, false, 0
	}
	if st.State == v1.DaemonRunning {
		next := now.Add(Backoff(st.Restarts))
		st.State, st.NextStart = v1.DaemonWaiting, &next
	}
	if st.NextStart != nil && now.Before(*st.NextStart) {
		return st, false, st.NextStart.Sub(now)
	}
	t := now
	st.State, st.StartedAt, st.NextStart = v1.DaemonRunning, &t, nil
	st.Restarts++
	return st, true, ProbeEvery
}

// CheckCommand and FixCommand run an upkeep task's scripts.
func CheckCommand(u v1.Upkeep) []string { return []string{"sh", "-c", as(u.User, u.Shell, u.Check)} }

// FixCommand runs the fix.
func FixCommand(u v1.Upkeep) []string { return []string{"sh", "-c", as(u.User, u.Shell, u.Fix)} }

// Due reports whether an upkeep task's check should run now, and otherwise when it will be.
func Due(u v1.Upkeep, st v1.UpkeepStatus, now time.Time) (bool, time.Duration) {
	every, err := time.ParseDuration(u.Every)
	if err != nil || every <= 0 {
		return false, 0
	}
	if st.LastCheck == nil {
		return true, 0
	}
	next := st.LastCheck.Add(every)
	if !now.Before(next) {
		return true, 0
	}
	return false, next.Sub(now)
}

// Outcome is how one run of an upkeep task went: the check's code, and, if the fix ran, its code
// and the check's code after it.
type Outcome struct {
	Check      int
	FixRan     bool
	Fix, After int
	Output     string // the end of what the failing part printed
}

// Result is the task's status after a run.
func Result(u v1.Upkeep, o Outcome, now time.Time) v1.UpkeepStatus {
	t := now
	st := v1.UpkeepStatus{Name: u.Name, LastCheck: &t}
	switch {
	case o.Check == 0:
		st.State = v1.UpkeepOK
	case o.FixRan && o.Fix == 0 && o.After == 0:
		st.State, st.LastFix = v1.UpkeepFixed, &t
	default:
		st.State = v1.UpkeepFailed
		if o.FixRan {
			st.LastFix = &t
		}
		st.Message = o.Output
	}
	return st
}

// Degraded reports whether any upkeep task failed, and which ones.
func Degraded(sts []v1.UpkeepStatus) []string {
	var out []string
	for _, s := range sts {
		if s.State == v1.UpkeepFailed {
			out = append(out, s.Name)
		}
	}
	return out
}
