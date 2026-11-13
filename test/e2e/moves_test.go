//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/container"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/worker"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/testbed"
)

// TestMoves is design §0.3 on two real workers: a docker silo with no local volume moves with
// kvo move silo NAME --to OTHER (the old host stops it first, then the new one starts it, and
// status.movingFrom clears); a cloud-hypervisor silo, on its host's local disk, is refused as
// pinned; and when a worker is lost, an onHostLoss: Recreate silo comes up on the other one, only
// after the lost host has fenced its copy, so two never run.
//
//	w1  control plane + worker with KVM (cloud-hypervisor) and docker
//	w2  worker with docker
func TestMoves(t *testing.T) {
	r := newRig(t, 50*time.Minute, map[string]testbed.Spec{
		"w1": {Role: "w1", CPUs: 4, Memory: "4GiB", Disk: "30GiB", KVM: true, Shared: true},
		"w2": {Role: "w2", CPUs: 3, Memory: "2GiB", Disk: "20GiB", Shared: true},
	})
	w1IP, w2IP := r.ip("w1"), r.ip("w2")
	t.Logf("w1 %s, w2 %s", w1IP, w2IP)
	r.must(kvoadm.Run, "", append(append([]string{"init"}, r.sshArgs("w1")...),
		"--name", "w1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--internal-ip", w1IP, "--worker",
		"--runtime", "cloud-hypervisor", "--runtime", "docker", "--loop-storage", "20G")...)
	r.must(kvoadm.Run, "", append(append([]string{"host", "add"}, r.sshArgs("w2")...),
		"--name", "w2", "--install", "worker", "--internal-ip", w2IP, "--server", "https://"+w1IP+":6443", "--runtime", "docker")...)
	t.Logf("kvoadm host list:\n%s", r.must(kvoadm.Run, "", "host", "list"))

	r.must(kvo.Run, `apiVersion: kevaso/v1
kind: Namespace
metadata: { name: mv }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: mover, namespace: mv }
spec:
  runtime: docker
  container: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 256Mi }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: stateless, namespace: mv }
spec:
  runtime: docker
  container: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 256Mi }
  availability: { onHostLoss: Recreate }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: pinned, namespace: mv }
spec:
  runtime: cloud-hypervisor
  vm: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
`, "apply", "-f", "-")
	r.waitRunning("mv", 30*time.Minute, "w1", "mover", "stateless", "pinned")
	wide, _ := r.kvo("", "get", "silos", "-n", "mv", "-o", "wide")
	t.Logf("kvo get silos -o wide:\n%s", wide)

	machineOf := map[string]string{"w1": "w1", "w2": "w2"}
	other := map[string]string{"w1": "w2", "w2": "w1"}
	mainOf := func(s *v1.Silo) string {
		return container.NamesFor(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID}).Main
	}
	// running says whether the silo's container runs on a host ("running", "stopped" or "absent").
	state := func(host, name string) string {
		out, err := r.sh(machineOf[host], "docker inspect --format '{{.State.Running}}' "+name+" 2>/dev/null || echo absent")
		switch strings.TrimSpace(out) {
		case "true":
			return "running"
		case "false":
			return "stopped"
		}
		if err != nil {
			return "unreachable"
		}
		return "absent"
	}
	// watchHandoff follows a silo's container on both hosts until it runs on to, and fails if it
	// ever runs on both at once.
	var lastStop time.Time // when watchHandoff last saw the old copy stop
	watchHandoff := func(what, name, from, to string, within time.Duration) {
		t.Helper()
		deadline := time.Now().Add(within)
		stoppedAt, startedAt := time.Time{}, time.Time{}
		for time.Now().Before(deadline) {
			f, g := state(from, name), state(to, name)
			if f == "running" && g == "running" {
				t.Errorf("%s: two copies run (on %s and %s)", what, from, to)
				return
			}
			if f != "running" && stoppedAt.IsZero() {
				stoppedAt = time.Now()
				lastStop = stoppedAt
				t.Logf("%s: stopped on %s (%s)", what, from, f)
			}
			if g == "running" {
				startedAt = time.Now()
				gap := startedAt.Sub(stoppedAt)
				t.Logf("%s: running on %s, %s after it stopped on %s", what, to, gap.Round(time.Second), from)
				if gap > 30*time.Second { // slow: what both agents said meanwhile
					since := stoppedAt.Add(-10 * time.Second).UTC().Format("2006-01-02 15:04:05")
					for _, h := range []string{from, to} {
						j, _ := r.sh(machineOf[h], "journalctl -u kevasod --utc --since '"+since+"' --no-pager | grep -v 'retry in' | tail -25")
						t.Logf("kevasod on %s meanwhile:\n%s", h, j)
					}
				}
				return
			}
			time.Sleep(time.Second)
		}
		t.Errorf("%s: never ran on %s (on %s: %s)\n%s", what, to, from, state(from, name), r.journal(to, 40))
	}

	// 1. A docker silo without local volumes moves, the old host stopping it first.
	mover := r.silo("mv", "mover")
	from, to := mover.Status.Host, other[mover.Status.Host]
	if mover.Status.Movable != "Anywhere" {
		t.Errorf("mover's movable: %q, want Anywhere", mover.Status.Movable)
	}
	out := r.must(kvo.Run, "", "move", "silo", "mover", "-n", "mv", "--to", to)
	expect(t, "kvo move silo", out, "moving to "+to+" with its data; "+from+" stops it first")
	if s := r.silo("mv", "mover"); s.Status.MovingFrom != from && s.Status.Phase != "Running" {
		t.Errorf("right after the move: movingFrom %q, host %s", s.Status.MovingFrom, s.Status.Host)
	}
	watchHandoff("mover", mainOf(mover), from, to, 3*time.Minute)
	r.eventually("the move is done: movingFrom clears", 2*time.Minute, func() (bool, string) {
		s := r.silo("mv", "mover")
		return s.Status.Host == to && s.Status.MovingFrom == "" && s.Status.Phase == "Running", fmt.Sprintf("host %s movingFrom %q phase %s", s.Status.Host, s.Status.MovingFrom, s.Status.Phase)
	})
	r.eventually("the old host let go of it", time.Minute, func() (bool, string) {
		st := state(from, mainOf(mover))
		return st == "absent", st
	})
	if out, code := r.in("mv", "mover", "hostname"); code != 0 {
		t.Errorf("exec after the move: %d %s", code, out)
	}

	// 2. A cloud-hypervisor silo keeps its disk on its host: refused as pinned.
	pinned := r.silo("mv", "pinned")
	if !strings.HasPrefix(pinned.Status.Movable, "Pinned") {
		t.Errorf("pinned's movable: %q", pinned.Status.Movable)
	}
	out, code := r.kvo("", "move", "silo", "pinned", "-n", "mv", "--to", other[pinned.Status.Host])
	if code == 0 || !strings.Contains(out, "not movable") {
		t.Errorf("moving a cloud-hypervisor silo: exit %d %q", code, out)
	} else {
		t.Logf("moving a cloud-hypervisor silo: refused: %s", firstLine(out))
	}
	if s := r.silo("mv", "pinned"); s.Status.Host != pinned.Status.Host || s.Status.Phase != "Running" {
		t.Errorf("the refused move changed it: %s %s", s.Status.Host, s.Status.Phase)
	}

	// 3. A Recreate silo on w2 (moved there first if it isn't), and w2 is lost.
	st := r.silo("mv", "stateless")
	if st.Status.Host != "w2" {
		r.must(kvo.Run, "", "move", "silo", "stateless", "-n", "mv", "--to", "w2")
		watchHandoff("stateless to w2", mainOf(st), "w1", "w2", 3*time.Minute)
		r.eventually("stateless is on w2", 2*time.Minute, func() (bool, string) {
			s := r.silo("mv", "stateless")
			return s.Status.Host == "w2" && s.Status.MovingFrom == "" && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
		})
	}
	name := mainOf(st)

	// 3a. w2's agent is alive but cut off from the control plane: it fences (stops the copy) before
	// the control plane, past the host lease and RecreateAfter, starts one on w1.
	if out, err := r.sh("w2", fmt.Sprintf(`nft -f - <<'NFT'
table inet cutoff {
  chain out { type filter hook output priority filter; policy accept; ip daddr %[1]s drop; }
  chain in { type filter hook input priority filter; policy accept; ip saddr %[1]s drop; }
}
NFT`, w1IP)); err != nil {
		t.Fatalf("cutting w2 off: %v %s", err, out)
	}
	cut := time.Now()
	watchHandoff("w2 cut off: stateless", name, "w2", "w1", 4*time.Minute)
	t.Logf("recreated on w1 %s after w2 was cut off", time.Since(cut).Round(time.Second))
	j, _ := r.sh("w2", "journalctl -u kevasod --no-pager | grep -i fenc | tail -3")
	expect(t, "w2's agent says it fenced", j, "fencing")
	r.eventually("stateless runs on w1", 2*time.Minute, func() (bool, string) {
		s := r.silo("mv", "stateless")
		return s.Status.Host == "w1" && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})
	// Back in touch, w2 removes its old copy (the silo is w1's now).
	if out, err := r.sh("w2", "nft delete table inet cutoff"); err != nil {
		t.Fatalf("reconnecting w2: %v %s", err, out)
	}
	r.eventually("w2, back, removes its old copy", 3*time.Minute, func() (bool, string) {
		s := state("w2", name)
		return s == "absent", s
	})
	r.eventually("w2 is Ready again", 3*time.Minute, func() (bool, string) {
		out, _ := r.kvo("", "get", "hosts")
		for _, l := range strings.Split(out, "\n") {
			if f := strings.Fields(l); len(f) > 1 && f[0] == "w2" {
				return strings.Contains(l, "Ready") && !strings.Contains(l, "NotReady") && !strings.Contains(l, "Lost"), l
			}
		}
		return false, out
	})

	// 3b–3d: w2's kevasod is gone, not just cut off. Its fence (kevaso-fence.service, a unit of
	// its own) stops the Recreate silo within FenceAfter; the control plane recreates it on w1
	// after the host lease and RecreateAfter; never two copies. A quick restart fences nothing.
	if out, _ := r.sh("w2", "systemctl is-active kevaso-fence.service"); strings.TrimSpace(out) != "active" {
		t.Fatalf("w2's fence isn't running: %q", out)
	}
	w2Ready := func(what string) {
		t.Helper()
		r.eventually(what+": w2 and its docker runtime Ready", 4*time.Minute, func() (bool, string) {
			out, _ := r.kvo("", "get", "hosts")
			for _, l := range strings.Split(out, "\n") {
				if f := strings.Fields(l); len(f) > 1 && f[0] == "w2" {
					return strings.Contains(l, "docker:Ready") && !strings.Contains(l, "NotReady") && !strings.Contains(l, "Lost"), l
				}
			}
			return false, out
		})
	}
	toW2 := func(what string) {
		t.Helper()
		w2Ready(what)
		r.must(kvo.Run, "", "move", "silo", "stateless", "-n", "mv", "--to", "w2")
		watchHandoff(what, name, "w1", "w2", 3*time.Minute)
		r.eventually(what+": on w2", 2*time.Minute, func() (bool, string) {
			s := r.silo("mv", "stateless")
			return s.Status.Host == "w2" && s.Status.MovingFrom == "" && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
		})
	}
	gone := func(what, how, back string) {
		t.Helper()
		toW2(what + ": stateless back to w2")
		if out, err := r.sh("w2", how); err != nil {
			t.Fatalf("%s: %v %s", how, err, out)
		}
		at := time.Now()
		lastStop = time.Time{}
		watchHandoff(what+": stateless", name, "w2", "w1", 4*time.Minute)
		if !lastStop.IsZero() {
			// The last contact can be a heartbeat old when kevasod goes, and a container's stop waits
			// out its grace (docker stop -t 20; sleep as PID 1 ignores SIGTERM): still well before
			// the control plane recreates it (host lease + RecreateAfter after the last heartbeat).
			if d, most := lastStop.Sub(at), agentFenceAfter+worker.DefaultHeartbeat+20*time.Second+5*time.Second; d > most {
				t.Errorf("%s: the old copy stopped %s after, past FenceAfter + a heartbeat + the stop's grace (%s)", what, d.Round(time.Second), most)
			} else {
				t.Logf("%s: the old copy stopped %s after (FenceAfter %s, at most %s with a heartbeat and the stop's grace)", what, d.Round(time.Second), agentFenceAfter, most)
			}
		}
		t.Logf("%s: recreated on w1 %s after", what, time.Since(at).Round(time.Second))
		fenced, _ := r.sh("w2", "journalctl -u kevaso-fence --no-pager --since '-5min' | grep 'fence: stopped' | tail -2")
		expect(t, what+": w2's fence stopped it", fenced, "fence: stopped mv/stateless (onHostLoss Recreate)")
		r.eventually(what+": stateless runs on w1", 2*time.Minute, func() (bool, string) {
			s := r.silo("mv", "stateless")
			return s.Status.Host == "w1" && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
		})
		if out, err := r.sh("w2", back); err != nil {
			t.Fatalf("%s: %v %s", back, err, out)
		}
		r.eventually(what+": w2's kevasod, back, removes its old copy", 3*time.Minute, func() (bool, string) {
			s := state("w2", name)
			return s == "absent", s
		})
	}
	// 3b. systemctl stop.
	gone("kevasod stopped", "systemctl stop kevasod", "systemctl start kevasod")
	// 3c. kill -9, and it stays dead (a crash systemd can't restart: Restart=no for this test).
	gone("kevasod killed", "mkdir -p /run/systemd/system/kevasod.service.d && printf '[Service]\\nRestart=no\\n' > /run/systemd/system/kevasod.service.d/e2e-norestart.conf && "+
		"systemctl daemon-reload && kill -9 $(systemctl show -p MainPID --value kevasod) && sleep 2 && ! systemctl is-active --quiet kevasod",
		"rm /run/systemd/system/kevasod.service.d/e2e-norestart.conf && systemctl daemon-reload && systemctl start kevasod")
	// 3d. A quick restart stops nothing: the silo keeps running on w2 throughout.
	toW2("restart")
	if out, err := r.sh("w2", "systemctl restart kevasod"); err != nil {
		t.Fatalf("restart: %v %s", err, out)
	}
	for end := time.Now().Add(agentFenceAfter + 30*time.Second); time.Now().Before(end); time.Sleep(2 * time.Second) {
		if st := state("w2", name); st != "running" {
			t.Fatalf("a quick restart of kevasod: the silo is %s on w2", st)
		}
		if st := state("w1", name); st == "running" {
			t.Fatal("a quick restart of kevasod: a copy runs on w1")
		}
	}
	if s := r.silo("mv", "stateless"); s.Status.Host != "w2" {
		t.Errorf("after a quick restart: on %s", s.Status.Host)
	} else {
		t.Logf("a quick restart of w2's kevasod: the silo kept running on w2 for %s", agentFenceAfter+30*time.Second)
	}
}

// agentFenceAfter is the agent's and the fence's default.
const agentFenceAfter = fence.DefaultAfter
