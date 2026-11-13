//go:build metal

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/sdk/kri"
)

// startTimes is each silo's start on its host: a container's StartedAt, a microVM unit's
// ActiveEnterTimestamp (read over SSH, so it works while the API is down).
func (p *pair) startTimes(ns string, silos ...string) map[string]string {
	p.t.Helper()
	out := map[string]string{}
	for _, n := range silos {
		s := p.c1.silo(ns, n)
		host := map[string]*mt{metalHost: p.c1, metalHost2: p.c2}[s.Status.Host]
		if host == nil {
			p.t.Fatalf("%s isn't placed", n)
		}
		if s.Spec.Runtime == "cloud-hypervisor" {
			unit := cloudhypervisor.NamesFor(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID}).Unit
			out[n] = s.Status.Host + " " + strings.TrimSpace(host.mustSh("systemctl show -p ActiveEnterTimestamp,ActiveState "+unit))
			continue
		}
		out[n] = s.Status.Host + " " + strings.TrimSpace(host.mustSh("docker ps -q --filter label=kevaso.com/uid="+s.UID+" | xargs -r docker inspect -f '{{.Name}} {{.State.StartedAt}}' | sort"))
	}
	return out
}

func sameStarts(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	ok := true
	for k, v := range before {
		if after[k] != v || strings.Contains(v, "inactive") {
			t.Errorf("%s: %s %q → %q", what, k, v, after[k])
			ok = false
		}
	}
	if ok {
		t.Logf("%s: no silo restarted", what)
	}
}

// TestMetal2ShortCut is the API unreachable from the worker for less than the fence time: a
// 15-second cut changes nothing, no silo stopped or restarted, the host never lost.
//
// Listens on nothing outside.
func TestMetal2ShortCut(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "shortcut2"
	c.namespace(ns)
	t.Cleanup(p.uncut)
	c.apply(boxEcho(ns, "stay", 8080) + on(metalHost2) + "---\n" + boxEcho(ns, "moves", 8080) + on(metalHost2) + "  availability: { onHostLoss: Recreate }\n---\n" +
		vmEcho(ns, "vm", 8080) + on(metalHost2))
	c.waitRunning(ns, 20*time.Minute, "stay", "moves", "vm")
	before := p.startTimes(ns, "stay", "moves", "vm")
	p.cut()
	time.Sleep(15 * time.Second)
	p.uncut()
	if fence.DefaultAfter <= 15*time.Second {
		t.Fatalf("the fence time (%s) isn't longer than the cut", fence.DefaultAfter)
	}
	time.Sleep(30 * time.Second)
	sameStarts(t, "a 15s cut", before, p.startTimes(ns, "stay", "moves", "vm"))
	for _, cd := range c.hostNamed(metalHost2).Status.Conditions {
		if cd.Type == "Ready" && cd.Status != "True" {
			t.Errorf("%s isn't Ready after a short cut: %+v", metalHost2, cd)
		}
	}
}

// TestMetal2RebootMidMove is the worker rebooted while a silo moves off it: the move completes
// on the other host and the rebooted one keeps no copy.
//
// Listens on nothing outside.
func TestMetal2RebootMidMove(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "midmove2"
	c.namespace(ns)
	c.apply(boxEcho(ns, "web", 8080))
	c.waitRunning(ns, 10*time.Minute, "web")
	if c.silo(ns, "web").Status.Host != metalHost2 {
		c.must("", "move", "silo", "web", "-n", ns, "--to", metalHost2)
		c.eventually("web on "+metalHost2, 5*time.Minute, func() (bool, string) {
			s := c.silo(ns, "web")
			return s.Status.Host == metalHost2 && s.Status.Phase == "Running" && s.Status.MovingFrom == "", s.Status.Host
		})
	}
	uid := c.silo(ns, "web").UID
	boot := strings.TrimSpace(p.c2.mustSh("cat /proc/sys/kernel/random/boot_id"))
	c.must("", "move", "silo", "web", "-n", ns, "--to", metalHost)
	_, _ = p.c2.sh("nohup sh -c 'sleep 1; systemctl reboot' >/dev/null 2>&1 &")
	_ = p.m2.d.Close()
	t.Log("moving web off machine 2, which reboots")
	p.waitBack(boot)
	c.eventually("the move completes on "+metalHost, 15*time.Minute, func() (bool, string) {
		s := c.silo(ns, "web")
		return s.Status.Host == metalHost && s.Status.Phase == "Running" && s.Status.MovingFrom == "", fmt.Sprint(s.Status.Host, s.Status.Phase, s.Status.MovingFrom)
	})
	c.eventually("machine 2 keeps no copy", 5*time.Minute, func() (bool, string) {
		out, _ := p.c2.sh("docker ps -aq --filter label=kevaso.com/uid=" + uid)
		return strings.TrimSpace(out) == "", out
	})
}

// waitBack waits for machine 2 to come back from a reboot (a new boot, the pinned host key) and
// be Ready.
func (p *pair) waitBack(boot string) {
	p.t.Helper()
	p.c1.eventually("machine 2 is back (a new boot, the pinned host key)", 15*time.Minute, func() (bool, string) {
		out, err := p.c2.sh("cat /proc/sys/kernel/random/boot_id")
		if err != nil {
			_ = p.m2.d.Close()
			return false, err.Error()
		}
		return strings.TrimSpace(out) != boot, out
	})
	p.c1.eventually(metalHost2+" Ready", 10*time.Minute, func() (bool, string) {
		h := p.c1.hostNamed(metalHost2)
		return meta(*h, "Ready"), fmt.Sprint(h.Status.Conditions)
	})
}

// TestMetal2Upgrade is kvoadm upgrade in place across both machines: kevasod rebuilt from the
// tree with another version string, every host reports it afterwards, and no silo restarted.
//
// Listens on nothing outside.
func TestMetal2Upgrade(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "upgrade2"
	c.namespace(ns)
	c.apply(boxEcho(ns, "a", 8080) + on(metalHost) + "---\n" + boxEcho(ns, "b", 8080) + on(metalHost2) + "---\n" + vmEcho(ns, "vm", 8080) + on(metalHost2))
	c.waitRunning(ns, 20*time.Minute, "a", "b", "vm")
	before := p.startTimes(ns, "a", "b", "vm")
	version := "e2e-" + strconv.FormatInt(time.Now().Unix(), 36)
	bin := filepath.Join(t.TempDir(), "kevasod")
	build := exec.CommandContext(c.ctx, "go", "build", "-o", bin, "-ldflags", "-X kevaso.com/core/internal/version.Version="+version, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+p.m1.arch, "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	var o bytes.Buffer
	if code := kvoadm.Run(c.ctx, []string{"upgrade", "--kevasod", bin, "--ssh-key", p.m1.cfg.KeyFile, "--version", version}, strings.NewReader(""), &o, &o); code != 0 {
		t.Fatalf("kvoadm upgrade: exit %d\n%s", code, o.String())
	}
	t.Logf("kvoadm upgrade:\n%s", o.String())
	for _, name := range []string{metalHost, metalHost2} {
		c.eventually(name+" runs "+version, 5*time.Minute, func() (bool, string) {
			h := c.hostNamed(name)
			return h.Status.Version == version && meta(*h, "Ready"), h.Status.Version
		})
	}
	c.waitRunning(ns, 5*time.Minute, "a", "b", "vm")
	sameStarts(t, "an upgrade", before, p.startTimes(ns, "a", "b", "vm"))
}

// TestMetal2MoveUnlikeStorage is a move between hosts whose storage differs (machine 1's
// loop file, machine 2's real disk when one is named): a container silo's data, checksummed,
// goes there and back. A microVM's disk can't move with its data (it's pinned): what it says.
//
// Listens on nothing outside.
func TestMetal2MoveUnlikeStorage(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "unlike2"
	c.namespace(ns)
	c.apply(boxEcho(ns, "web", 8080) + "---\n" + vmEcho(ns, "vm", 8080) + on(metalHost))
	c.waitRunning(ns, 20*time.Minute, "web", "vm")
	sum, _ := c.in(ns, "web", "head -c 16M /dev/urandom > /root/blob && sync && sha256sum /root/blob | cut -d' ' -f1")
	if len(sum) != 64 {
		t.Fatalf("write: %q", sum)
	}
	for i := 0; i < 2; i++ {
		from := c.silo(ns, "web").Status.Host
		to := map[string]string{metalHost: metalHost2, metalHost2: metalHost}[from]
		c.must("", "move", "silo", "web", "-n", ns, "--to", to)
		c.eventually("web on "+to, 10*time.Minute, func() (bool, string) {
			s := c.silo(ns, "web")
			return s.Status.Host == to && s.Status.Phase == "Running" && s.Status.MovingFrom == "", s.Status.Host + " " + s.Status.Phase
		})
		got, _ := c.in(ns, "web", "sha256sum /root/blob 2>&1 | cut -d' ' -f1")
		if got != sum {
			t.Errorf("after the move %s → %s the data's sum is %q, want %s", from, to, got, sum)
		} else {
			t.Logf("%s → %s: the data is intact (sha256 %s…)", from, to, sum[:12])
		}
	}
	if out, code := c.kvo("", "move", "silo", "vm", "-n", ns, "--to", metalHost2); code == 0 {
		t.Errorf("a microVM moved: %s", out)
	} else {
		t.Logf("a microVM between unlike storage: %s", strings.TrimSpace(out))
	}
}

// hostLeaks is what a host holds of silos: compared before and after the soak.
func (p *pair) hostLeaks(c *mt) map[string]string {
	p.t.Helper()
	got := map[string]string{}
	for k, script := range map[string]string{
		"taps and veths":       `ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -c '^kv[tp]' || true`,
		"bridge ports":         `bridge link show 2>/dev/null | grep -c 'master kvbr0' || true`,
		"nft rules":            `nft -a list ruleset 2>/dev/null | grep -c 'handle' || true`,
		"secret tmpfs mounts":  `grep -c ' /run/kevaso-secrets' /proc/mounts || true`,
		"logical volumes":      `lvs --noheadings -o lv_name kevaso 2>/dev/null | grep -c 'kv-' || true`,
		"VMMs":                 `pgrep -c -x "$(printf %.15s cloud-hypervisor)" || true`,
		"containers":           `docker ps -aq | wc -l`,
		"container volumes":    `docker volume ls -q | wc -l`,
		"silo state dirs":      `ls /var/lib/kevaso-silos /var/lib/kevaso-containers 2>/dev/null | grep -vc ':$' || true`,
		"kevaso-silo-* units":  `systemctl list-units --all --plain --no-legend 'kevaso-silo-*' | wc -l`,
		"fence record entries": `grep -o '"uid"' ` + fence.Dir + `/` + fence.RecordFile + ` 2>/dev/null | wc -l`,
	} {
		got[k] = strings.TrimSpace(c.mustSh(script))
	}
	return got
}

// TestMetal2Soak is 30 silos (mixed runtimes, both hosts) made, checked by name from a silo,
// and deleted, three times over; afterwards neither host holds more than before: taps, bridge
// ports, nft rules, secret mounts, logical volumes, VMMs, containers, state, units, names.
//
// Listens on nothing outside.
func TestMetal2Soak(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "soak2"
	c.namespace(ns)
	c.apply(vmEcho(ns, "probe", 8080) + on(metalHost))
	c.waitRunning(ns, 15*time.Minute, "probe")
	before := map[string]map[string]string{metalHost: p.hostLeaks(p.c1), metalHost2: p.hostLeaks(p.c2)}
	const n = 30
	for round := 1; round <= 3; round++ {
		var b strings.Builder
		var names []string
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("s%02d", i)
			names = append(names, name)
			host := []string{metalHost, metalHost2}[i%2]
			doc := boxEcho(ns, name, 8080)
			if i%5 == 0 {
				doc = vmEcho(ns, name, 8080)
				doc = strings.Replace(doc, "memory: 768Mi", "memory: 512Mi", 1)
			}
			b.WriteString(doc + on(host) + "  ports: [{ name: http, port: 8080 }]\n  service:\n    ports: [{ port: http, allowFrom: [probe] }]\n---\n")
		}
		c.apply(b.String())
		c.waitRunning(ns, 30*time.Minute, names...)
		for _, name := range names {
			c.eventually(fmt.Sprintf("round %d: %s answers by name", round, name), 2*time.Minute, func() (bool, string) {
				out, _ := c.in(ns, "probe", "curl -sS --max-time 5 http://"+name+":8080/")
				return strings.Contains(out, name+" 8080"), out
			})
		}
		for _, name := range names {
			c.must("", "delete", "silo", name, "-n", ns)
		}
		c.eventually(fmt.Sprintf("round %d: all deleted", round), 10*time.Minute, func() (bool, string) {
			out, _ := c.kvo("", "get", "silos", "-n", ns, "-o", "json")
			return len(metalSilos(out)) == 1, fmt.Sprint(len(metalSilos(out)), " left")
		})
		gone, _ := c.in(ns, "probe", "getent ahostsv4 s00 || echo none")
		if !strings.Contains(gone, "none") {
			t.Errorf("round %d: a deleted silo's name still resolves: %s", round, gone)
		}
		t.Logf("round %d done", round)
	}
	time.Sleep(30 * time.Second)
	for host, c2 := range map[string]*mt{metalHost: p.c1, metalHost2: p.c2} {
		after := p.hostLeaks(c2)
		for k, v := range before[host] {
			if after[k] != v {
				t.Errorf("%s: %s %s before, %s after three rounds", host, k, v, after[k])
			}
		}
		b, _ := json.Marshal(after)
		t.Logf("%s after the soak: %s", host, b)
	}
}
