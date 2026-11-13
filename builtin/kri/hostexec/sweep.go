package hostexec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"kevaso.com/core/sdk/kri"
)

// Stopping what one Exec started when its client goes away: the runtime's own client (docker
// exec, ssh, openshell's CLI) doesn't do that. The command carries a marker (kri.ExecMarkerEnv);
// what it started is found from three things, so a command that clears its environment (env -i)
// doesn't escape:
//
//   - processes whose environment holds the marker, or whose command line does (a parent the
//     runtime keeps alive for the command: the VM's ssh session shell);
//   - roots the runtime found itself (a container exec's first process, seen from the host);
//   - everything below them: their descendants, and every process in a session one of them leads
//     (each exec is a session of its own: runc and crun setsid it, sshd does for a session).
//
// The sweep stops (SIGSTOP) what it finds, looks again until nothing new turns up, then kills it
// all: a process forking during the sweep is stopped before its child can be missed. What still
// escapes: a process that left the tree and the session (a daemon: fork, setsid, exit the parent)
// and cleared the marker from its environment, before the sweep.

// NewMarker returns a value for kri.ExecMarkerEnv, unique to one Exec.
func NewMarker() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Proc is one process as a sweep sees it.
type Proc struct {
	PID, PPID, SID int
	Marked         bool // its environment or command line holds the marker
}

// parseStat reads the state, parent and session from /proc/PID/stat ("pid (comm) state ppid pgrp
// sid …"; comm may hold spaces and parentheses, so it's cut at the last ")").
func parseStat(b []byte) (state string, ppid, sid int, ok bool) {
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return "", 0, 0, false
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 4 {
		return "", 0, 0, false
	}
	ppid, err1 := strconv.Atoi(f[1])
	sid, err2 := strconv.Atoi(f[3])
	return f[0], ppid, sid, err1 == nil && err2 == nil
}

func hasMarker(environ, cmdline []byte, marker string) bool {
	want := kri.ExecMarkerEnv + "=" + marker
	for v := range bytes.SplitSeq(environ, []byte{0}) {
		if string(v) == want {
			return true
		}
	}
	// On a command line it's part of an argument (sh -c "… env KEVASO_EXEC=M …"): the marker is
	// random hex, so a match on the whole word is it.
	for v := range bytes.SplitSeq(cmdline, []byte{0}) {
		for _, w := range strings.Fields(string(v)) {
			if w == want {
				return true
			}
		}
	}
	return false
}

// Snapshot reads every process on this host (or in this silo, run in it).
func Snapshot(r Runner, marker string) map[int]Proc { return scan(r, marker, nil) }

// scan is Snapshot of the processes keep wants (by their stat; nil: all), reading their
// environment and command line only for those.
func scan(r Runner, marker string, keep func(Proc) bool) map[int]Proc {
	files, _ := r.Glob("/proc/[0-9]*/stat")
	envs, _ := r.Glob("/proc/[0-9]*/environ")
	dirs := map[string]bool{}
	for _, f := range append(files, envs...) {
		dirs[f[:strings.LastIndexByte(f, '/')]] = true
	}
	out := map[int]Proc{}
	for d := range dirs {
		pid, err := strconv.Atoi(strings.TrimPrefix(d, "/proc/"))
		if err != nil || pid <= 1 {
			continue
		}
		p := Proc{PID: pid}
		if b, err := r.ReadFile(d + "/stat"); err == nil {
			var state string
			state, p.PPID, p.SID, _ = parseStat(b)
			if state == "Z" || state == "X" {
				continue // dead already, waiting for its parent to reap it
			}
		}
		if keep != nil && !keep(p) {
			continue
		}
		env, _ := r.ReadFile(d + "/environ")
		cmd, _ := r.ReadFile(d + "/cmdline")
		p.Marked = marker != "" && hasMarker(env, cmd, marker)
		out[pid] = p
	}
	return out
}

// Members are the processes of one Exec in procs: the marked ones and roots, their descendants,
// and the sessions they lead (a root's, even if it has exited). Never PID 1 (a container's or VM's init). Sorted.
func Members(procs map[int]Proc, roots []int) []int {
	in := map[int]bool{}
	for _, p := range procs {
		if p.Marked {
			in[p.PID] = true
		}
	}
	// A root leads its session (ExecRoot finds session leaders), even once it has exited: Linux
	// doesn't reuse a PID while it is still some process's session ID.
	led := map[int]bool{}
	for _, r := range roots {
		if _, ok := procs[r]; ok {
			in[r] = true
		}
		led[r] = r > 1
	}
	for grew := true; grew; {
		grew = false
		for _, p := range procs {
			if in[p.PID] {
				continue
			}
			if in[p.PPID] || led[p.SID] || (p.SID > 1 && in[p.SID] && procs[p.SID].SID == p.SID) {
				in[p.PID], grew = true, true
			}
		}
	}
	out := make([]int, 0, len(in))
	for p := range in {
		if p > 1 {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// Sweep stops every member of one Exec until no new one turns up, then kills them all (SIGKILL),
// and returns how many.
func Sweep(ctx context.Context, r Runner, marker string, roots []int) int {
	stopped := map[int]bool{}
	known := slices.Clone(roots)
	for range 16 { // each round finds what forked before its parent was stopped
		var fresh []int
		for _, p := range Members(Snapshot(r, marker), known) {
			if !stopped[p] {
				fresh = append(fresh, p)
			}
		}
		if len(fresh) == 0 {
			break
		}
		signal(ctx, r, "-STOP", fresh)
		for _, p := range fresh {
			stopped[p] = true
			known = append(known, p)
		}
	}
	all := make([]int, 0, len(stopped))
	for p := range stopped {
		all = append(all, p)
	}
	slices.Sort(all)
	signal(ctx, r, "-KILL", all)
	return len(all)
}

func signal(ctx context.Context, r Runner, sig string, pids []int) {
	if len(pids) == 0 {
		return
	}
	args := []string{sig}
	for _, p := range pids {
		args = append(args, strconv.Itoa(p))
	}
	_, _ = r.Run(ctx, Cmd{Name: "kill", Args: args})
}

// ExecRoot finds, on the host, the first process of an exec just started in a container: a
// session leader in the container's cgroup (that of its init, initPID) whose parent is outside it
// (the engine's shim or conmon), not among before. Marked ones first; an unmarked one only when
// it's the only new one (it cleared its environment already). 0: not (yet) found.
func ExecRoot(r Runner, initPID int, before map[int]bool, marker string) int {
	cg, err := r.ReadFile("/proc/" + strconv.Itoa(initPID) + "/cgroup")
	if err != nil || len(cg) == 0 {
		return 0
	}
	in := func(pid int) bool {
		b, err := r.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
		return err == nil && bytes.Equal(b, cg)
	}
	var unmarked []int
	procs := scan(r, marker, func(p Proc) bool { return p.SID == p.PID && p.PID != initPID && !before[p.PID] })
	pids := make([]int, 0, len(procs))
	for p := range procs {
		pids = append(pids, p)
	}
	slices.Sort(pids)
	for _, pid := range pids {
		p := procs[pid]
		if pid == initPID || before[pid] || p.SID != pid || !in(pid) || in(p.PPID) {
			continue
		}
		if p.Marked {
			return pid
		}
		env, _ := r.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
		if !bytes.Contains(env, []byte(kri.ExecMarkerEnv+"=")) { // not another exec's
			unmarked = append(unmarked, pid)
		}
	}
	if len(unmarked) == 1 {
		return unmarked[0]
	}
	return 0
}

// SessionLeaders are the container's session leaders now (initPID's cgroup): what ExecRoot
// leaves out as already there.
func SessionLeaders(r Runner, initPID int) map[int]bool {
	cg, err := r.ReadFile("/proc/" + strconv.Itoa(initPID) + "/cgroup")
	out := map[int]bool{}
	if err != nil {
		return out
	}
	for pid := range scan(r, "", func(p Proc) bool { return p.SID == p.PID }) {
		if b, err := r.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup"); err == nil && bytes.Equal(b, cg) {
			out[pid] = true
		}
	}
	return out
}

// holdScript keeps a shell as the command's parent, its $0 the marker, for as long as the command
// runs (no exec: `; exit $?` keeps sh from replacing itself with the last command). INT and QUIT
// get a handler, not "ignore", so the shell waits out a ^C its command handles, and the command
// still gets them (handlers, unlike ignored signals, reset on exec).
const holdScript = `trap : INT QUIT; "$@"; exit $?`

// Held is cmd run under a shell that holds the marker on its command line, and with the marker in
// its environment: for a runtime that starts the command with nothing of its own left around it
// (an OpenShell sandbox), so a command that clears its environment is still below a marked
// process. It needs sh in the image, as SweepScript does.
func Held(marker string, cmd []string) []string {
	m := kri.ExecMarkerEnv + "=" + marker
	return append([]string{"sh", "-c", holdScript, m, "env", m}, cmd...)
}

// SweepScript is the same sweep run inside a silo with sh, for runtimes whose host doesn't see the
// silo's processes (a VM, an OpenShell sandbox): `sh -c SweepScript sh MARKER`. It needs only sh,
// tr, grep and kill, which every Linux image with a shell has. It never touches itself, its
// ancestors (the session that runs it) or PID 1.
const SweepScript = `m="` + kri.ExecMarkerEnv + `=$1"; self=$$; skip=" 1 "; p=$self; ` +
	// itself and its ancestors
	`while [ "$p" -gt 1 ] 2>/dev/null; do skip="$skip$p "; read -r s < /proc/$p/stat || break; s=${s##*) }; set -- $s; p=$2; done; ` +
	`in=" "; stopped=" "; r=0; while [ $r -lt 16 ]; do r=$((r+1)); new=""; ` +
	`for f in /proc/[0-9]*/stat; do d=${f%/stat}; p=${d#/proc/}; ` +
	`case "$skip$stopped" in *" $p "*) continue;; esac; ` +
	`read -r s < "$f" 2>/dev/null || continue; s=${s##*) }; set -- $s; [ "$1" = Z ] && continue; pp=$2; sid=$4; hit=; ` +
	`[ "$pp" = "$self" ] && continue; ` + // its own tr and grep
	`case "$in" in *" $pp "*|*" $sid "*) hit=1;; esac; ` +
	`[ -z "$hit" ] && { tr '\000' '\n' < $d/environ 2>/dev/null | grep -qxF "$m" && hit=1; }; ` +
	`[ -z "$hit" ] && { tr '\000 ' '\n\n' < $d/cmdline 2>/dev/null | grep -qxF "$m" && hit=1; }; ` +
	`[ -n "$hit" ] && { new="$new $p"; in="$in$p "; }; done; ` +
	`[ -z "$new" ] && break; kill -STOP $new 2>/dev/null; stopped="$stopped${new# } "; done; ` +
	`[ "$stopped" != " " ] && kill -KILL $stopped 2>/dev/null; true`
