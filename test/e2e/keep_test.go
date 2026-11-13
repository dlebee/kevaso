//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed"
)

// TestDaemonsAndUpkeep is design §0.5 on real machines, on cloud-hypervisor and on docker: the host's
// agent starts a silo's daemons through the runtime's exec (nothing of Kevaso's in the silo), one
// as root and one as another user; killing a daemon inside the silo gets it started again with
// restarts going up; an upkeep task whose check fails runs its fix (Fixed), one whose fix doesn't
// help marks the silo Degraded until its check passes again; kvo describe silo shows both tables.
// On docker it also shows what happens in an image without setsid and su.
//
//	metal-1  control plane + worker with KVM (cloud-hypervisor) and docker
func TestDaemonsAndUpkeep(t *testing.T) {
	r := newRig(t, 45*time.Minute, map[string]testbed.Spec{
		"metal": {Role: "metal", CPUs: 4, Memory: "5GiB", Disk: "40GiB", KVM: true, Shared: true},
	})
	metalIP := r.ip("metal")
	r.must(kvoadm.Run, "", append(append([]string{"init"}, r.sshArgs("metal")...),
		"--name", "metal-1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--address", metalIP, "--worker",
		"--runtime", "cloud-hypervisor", "--runtime", "docker", "--loop-storage", "30G")...)
	r.must(kvo.Run, "apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: keep }\n", "apply", "-f", "-")
	silo := func(name, runtime, extra string) string {
		return fmt.Sprintf(`---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: %s, namespace: keep }
spec:
  runtime: %s
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 768Mi }
%s  daemons:
    - name: ticker
      run: while true; do date +%%s > /tmp/tick; sleep 2; done
    - name: as-nobody
      user: nobody
      run: while true; do id -un > /tmp/whoami; sleep 2; done
  upkeep:
    - name: marker
      every: 1m
      check: test -f /tmp/marker
      fix: touch /tmp/marker
    - name: broken
      every: 1m
      check: test -f /tmp/fixed-by-hand
      fix: echo this fix cannot help >&2; exit 3
`, name, runtime, extra)
	}
	r.must(kvo.Run, silo("vm", "cloud-hypervisor", "  disk: { size: 5Gi }\n")+silo("box", "docker", ""), "apply", "-f", "-")
	r.waitRunning("keep", 30*time.Minute, "metal", "vm", "box")

	for _, name := range []string{"vm", "box"} {
		t.Run(name, func(t *testing.T) {
			r := r.on(t)
			tools, _ := r.in("keep", name, "for c in setsid su; do command -v $c >/dev/null && echo $c=yes || echo $c=no; done")
			t.Logf("in %s's image: %s", name, strings.ReplaceAll(tools, "\n", " "))
			daemon := func(d string) v1.DaemonStatus {
				for _, st := range r.silo("keep", name).Status.Daemons {
					if st.Name == d {
						return st
					}
				}
				return v1.DaemonStatus{}
			}
			upkeep := func(u string) v1.UpkeepStatus {
				for _, st := range r.silo("keep", name).Status.Upkeep {
					if st.Name == u {
						return st
					}
				}
				return v1.UpkeepStatus{}
			}
			// Started, as the right user.
			r.eventually("the daemons are started", 2*time.Minute, func() (bool, string) {
				out, _ := r.in("keep", name, "t=$(cat /tmp/tick); [ $(( $(date +%s) - t )) -le 5 ] && cat /tmp/whoami")
				return out == "nobody" && daemon("ticker").State == v1.DaemonRunning && daemon("as-nobody").State == v1.DaemonRunning, out
			})
			// Killed inside the silo (its whole process group, with the kill dash takes): started again, restarts goes up.
			before := daemon("ticker").Restarts
			tree := "echo pid=$(cat /run/kevaso/daemons/ticker.pid); ls /run/kevaso/daemons; ps -eo pid,ppid,pgid,sid,stat,args | grep -v ' ps -eo' | grep -E 'tick|sleep|PID'"
			pre, _ := r.in("keep", name, tree)
			if out, code := r.in("keep", name, "kill -s KILL -- -$(cat /run/kevaso/daemons/ticker.pid)"); code != 0 {
				t.Fatalf("kill: %d %s", code, out)
			}
			post, _ := r.in("keep", name, tree)
			if !r.eventually("a killed daemon is started again", 2*time.Minute, func() (bool, string) {
				st := daemon("ticker")
				out, _ := r.in("keep", name, "kill -0 $(cat /run/kevaso/daemons/ticker.pid) && echo alive")
				return st.State == v1.DaemonRunning && st.Restarts == before+1 && out == "alive", fmt.Sprintf("%+v %s", st, out)
			}) {
				now, _ := r.in("keep", name, tree)
				t.Logf("before the kill:\n%s\nright after:\n%s\nnow:\n%s\nkevasod:\n%s", pre, post, now, r.journal("metal", 30))
			}
			// Upkeep: the marker is put back by its fix; the broken one marks the silo Degraded.
			r.eventually("a failing check runs its fix", 3*time.Minute, func() (bool, string) {
				st := upkeep("marker")
				out, _ := r.in("keep", name, "test -f /tmp/marker && echo there")
				return (st.State == v1.UpkeepFixed || st.State == v1.UpkeepOK) && st.LastFix != nil && out == "there", fmt.Sprintf("%+v", st)
			})
			r.eventually("a fix that doesn't help: Degraded", 3*time.Minute, func() (bool, string) {
				s := r.silo("keep", name)
				st := upkeep("broken")
				return st.State == v1.UpkeepFailed && strings.Contains(st.Message, "this fix cannot help") && condTrue(s, "Degraded"), fmt.Sprintf("%+v %v", st, s.Status.Conditions)
			})
			desc := r.must(kvo.Run, "", "describe", "silo", name, "-n", "keep")
			t.Logf("kvo describe silo %s:\n%s", name, desc)
			for _, want := range []string{"Daemons:", "Upkeep:", "RESTARTS", "LAST EXIT", "LAST CHECK", "ticker", "as-nobody", "marker", "broken", "Failed", "this fix cannot help"} {
				if !strings.Contains(desc, want) {
					t.Errorf("describe doesn't show %q", want)
				}
			}
			// Fixed by hand: the next check passes and Degraded goes away.
			r.in("keep", name, "touch /tmp/fixed-by-hand")
			r.eventually("fixed by hand: no longer Degraded", 3*time.Minute, func() (bool, string) {
				s := r.silo("keep", name)
				return upkeep("broken").State == v1.UpkeepOK && !condTrue(s, "Degraded"), fmt.Sprintf("%+v", upkeep("broken"))
			})
		})
	}

	// An image without setsid and su (here: the docker silo with them taken away). A root daemon
	// still starts (setsid is optional: only a stop is less thorough); one with a user can't, and
	// says so with exit code 127, restarted with a growing backoff.
	t.Run("without setsid and su", func(t *testing.T) {
		r := r.on(t)
		if out, code := r.in("keep", "box", `for c in setsid su; do p=$(command -v $c) && mv "$p" "$p.off"; done; command -v setsid su || echo gone`); code != 0 || out != "gone" {
			t.Fatalf("taking setsid and su away: %d %q", code, out)
		}
		defer r.in("keep", "box", `for p in /usr/bin/setsid.off /usr/bin/su.off /bin/setsid.off /bin/su.off; do [ -e "$p" ] && mv "$p" "${p%.off}"; done; true`)
		daemon := func(d string) v1.DaemonStatus {
			for _, st := range r.silo("keep", "box").Status.Daemons {
				if st.Name == d {
					return st
				}
			}
			return v1.DaemonStatus{}
		}
		before, nb := daemon("ticker").Restarts, daemon("as-nobody").Restarts
		r.in("keep", "box", "for d in ticker as-nobody; do p=$(cat /run/kevaso/daemons/$d.pid); kill -s KILL -- -$p 2>/dev/null || kill -s KILL $p; done; true")
		r.eventually("without setsid, a root daemon is still started again", 2*time.Minute, func() (bool, string) {
			st := daemon("ticker")
			out, _ := r.in("keep", "box", "t=$(cat /tmp/tick); [ $(( $(date +%s) - t )) -le 5 ] && echo ticking")
			return st.State == v1.DaemonRunning && st.Restarts > before && out == "ticking", fmt.Sprintf("%+v %s", st, out)
		})
		r.eventually("without su, a user's daemon can't start: exit 127, restarted with a backoff", 3*time.Minute, func() (bool, string) {
			st := daemon("as-nobody")
			return st.Restarts >= nb+2 && st.ExitCode != nil && *st.ExitCode == 127, fmt.Sprintf("%+v", st)
		})
		desc := r.must(kvo.Run, "", "describe", "silo", "box", "-n", "keep")
		t.Logf("kvo describe silo box without setsid and su:\n%s", desc)
		log, _ := r.in("keep", "box", "tail -3 /run/kevaso/daemons/as-nobody.log")
		t.Logf("as-nobody's log: %s", log)
	})
}

func condTrue(s *v1.Silo, typ string) bool {
	for _, c := range s.Status.Conditions {
		if c.Type == typ {
			return c.Status == "True"
		}
	}
	return false
}
