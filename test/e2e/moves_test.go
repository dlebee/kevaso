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
		"--name", "w1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--address", w1IP, "--worker",
		"--runtime", "cloud-hypervisor", "--runtime", "docker", "--loop-storage", "20G")...)
	r.must(kvoadm.Run, "", append(append([]string{"host", "add"}, r.sshArgs("w2")...),
		"--name", "w2", "--install", "worker", "--address", w2IP, "--server", "https://"+w1IP+":6443", "--runtime", "docker")...)
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
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 256Mi }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: stateless, namespace: mv }
spec:
  runtime: docker
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 256Mi }
  availability: { onHostLoss: Recreate }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: pinned, namespace: mv }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
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

	// 3b. w2's kevasod is stopped. Back to w2 first.
	r.must(kvo.Run, "", "move", "silo", "stateless", "-n", "mv", "--to", "w2")
	watchHandoff("stateless back to w2", name, "w1", "w2", 3*time.Minute)
	r.eventually("stateless is on w2 again", 2*time.Minute, func() (bool, string) {
		s := r.silo("mv", "stateless")
		return s.Status.Host == "w2" && s.Status.MovingFrom == "" && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})
	if out, err := r.sh("w2", "systemctl stop kevasod"); err != nil {
		t.Fatalf("stopping w2's kevasod: %v %s", err, out)
	}
	stopped := time.Now()
	watchHandoff("w2's kevasod stopped: stateless", name, "w2", "w1", 4*time.Minute)
	t.Logf("recreated on w1 %s after w2's kevasod stopped", time.Since(stopped).Round(time.Second))
	r.eventually("w2 is lost and stateless runs on w1", 2*time.Minute, func() (bool, string) {
		s := r.silo("mv", "stateless")
		return s.Status.Host == "w1" && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})
	if s := r.silo("mv", "mover"); s.Status.Host == "w2" {
		t.Logf("mover (onHostLoss: Wait) stays on lost w2: %s", s.Status.Phase)
	}
	if out, err := r.sh("w2", "systemctl start kevasod"); err != nil {
		t.Fatalf("starting w2's kevasod: %v %s", err, out)
	}
	r.eventually("w2's kevasod, back, removes its old copy", 3*time.Minute, func() (bool, string) {
		s := state("w2", name)
		return s == "absent", s
	})
}
