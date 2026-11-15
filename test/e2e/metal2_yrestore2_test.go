//go:build metal

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
)

// The reset gate's restores: machine 1's control plane reset and restored from a backup while
// machine 2 runs on. They need the cluster this run made (its recovery key).

// restorer backs up the cluster and restores machine 1's control plane from a backup.
type restorer struct {
	p    *pair
	t    *testing.T
	ssh  []string
	file string
}

func newRestorer(t *testing.T, p *pair) *restorer {
	if p.recoveryKey == "" {
		t.Skip("needs the cluster this run made (its recovery key): not with KEVASO_METAL_REUSE")
	}
	cfg := p.m1.cfg
	return &restorer{p: p, t: t, file: filepath.Join(t.TempDir(), "gate.kvb"),
		ssh: []string{cfg.SSHTarget(), "--ssh-port", strconv.Itoa(cfg.Port), "--ssh-key", cfg.KeyFile, "--host-key", cfg.HostKey}}
}

func (r *restorer) kvoadm(stdin string, args ...string) string {
	r.t.Helper()
	var o bytes.Buffer
	if code := kvoadm.Run(r.p.c1.ctx, args, strings.NewReader(stdin), &o, &o); code != 0 {
		r.t.Fatalf("kvoadm %s: exit %d\n%s", args[0], code, metalRedact(o.String()))
	}
	return metalRedact(o.String())
}

func (r *restorer) backup() {
	r.t.Helper()
	r.t.Log(r.kvoadm("", append(append([]string{"backup"}, r.ssh...), "--output", r.file)...))
}

// restore resets machine 1 and restores it from the backup; machine 2 Ready again after.
func (r *restorer) restore() {
	r.t.Helper()
	cfg := r.p.m1.cfg
	_ = r.p.m1.d.Close()
	r.t.Log(r.kvoadm("", append(append([]string{"reset"}, r.ssh...), "--force", "--yes")...))
	out := r.kvoadm(r.p.recoveryKey+"\n", append(append([]string{"init"}, r.ssh...), "--kevasod", r.p.bin, "--no-extra-hardening", "--restore", r.file,
		"--api-server", "https://"+net.JoinHostPort(cfg.ExternalIP, "6443"), "--external-ip", cfg.ExternalIP)...)
	r.t.Logf("kvoadm init --restore:\n%s", out)
	r.p.mu.Lock()
	r.p.m1Worker = false
	r.p.mu.Unlock()
	c := r.p.c1
	c.eventually(metalHost2+" is Ready with the restored control plane", 10*time.Minute, func() (bool, string) { return c.hostReady(metalHost2) })
}

// TestMetal2RestoreDuringStart is the restore-during-start case: a backup, then a microVM with a
// volume placed on machine 2 and still starting (a slow init step) when machine 1's control plane
// is restored from that backup. On machine 2 its root disk and volume stay, and the restored
// control plane's Host lists it in KeptSilos with its UID. Then restored a second time from the
// same backup: the same.
//
// Listens on nothing outside.
func TestMetal2RestoreDuringStart(t *testing.T) {
	p := metal2(t)
	r := newRestorer(t, p)
	c := p.c1
	ns := "restorestart2"
	c.namespace(ns)
	r.backup()
	c.apply(vmEcho(ns, "vm", 8080) + on(metalHost2) + "  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n" +
		"  init: { steps: [{ name: slow, run: \"sleep 900\" }] }\n")
	c.eventually("its microVM runs, the silo still starting", 15*time.Minute, func() (bool, string) {
		s := c.silo(ns, "vm")
		if s.Status.Phase == "Running" {
			t.Fatal("it ran before the restore: the init step didn't hold it")
		}
		if s.UID == "" {
			return false, "no uid"
		}
		n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: s.UID})
		out := strings.TrimSpace(p.c2.mustSh("systemctl is-active " + n.Unit + " || true"))
		return out == "active" && claimTime(s) != "", out + " claim " + claimTime(s)
	})
	s := c.silo(ns, "vm")
	uid := s.UID
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: uid})
	t.Cleanup(func() { // the copy is kept on purpose: removed by hand, as the runtime's Delete would
		_, _ = p.c2.sh("systemctl stop " + n.Unit + " 2>/dev/null; rm -f /etc/systemd/system/" + n.Unit + "; systemctl daemon-reload; " +
			"ip link del " + n.Tap + " 2>/dev/null; for lv in $(lvs --noheadings -o lv_name kevaso | grep " + n.LV + "); do lvremove -q -y kevaso/$lv; done; rm -rf " + n.Dir + "; true")
	})
	lvs := func() string {
		return strings.TrimSpace(p.c2.mustSh("lvs --noheadings -o lv_name kevaso | tr -d ' ' | grep '^" + n.LV + "' | sort | tr '\\n' ' '"))
	}
	before := lvs()
	t.Logf("starting on machine 2 (claim %s), its LVs: %s", claimTime(s), before)
	for i := 1; i <= 2; i++ {
		r.restore()
		if o, code := c.kvo("", "get", "silo", "vm", "-n", ns); code == 0 {
			t.Fatalf("restore %d: the restored state knows the silo made after the backup: %s", i, o)
		}
		c.eventually(fmt.Sprintf("restore %d: KeptSilos names it with its UID", i), 5*time.Minute, func() (bool, string) {
			k := meta.FindCondition(c.hostNamed(metalHost2).Status.Conditions, agent.ConditionKeptSilos)
			return k != nil && k.Status == meta.ConditionTrue && strings.Contains(k.Message, ns+"/vm") && strings.Contains(k.Message, uid[:8]), fmt.Sprint(k)
		})
		if now := lvs(); now != before {
			t.Errorf("restore %d: its LVs were %q, now %q (root disk and volume must stay)", i, before, now)
		}
		t.Logf("restore %d: unit %s; KeptSilos: %s", i, p.c2.mustSh("systemctl is-active "+n.Unit+" || true"),
			meta.FindCondition(c.hostNamed(metalHost2).Status.Conditions, agent.ConditionKeptSilos).Message)
	}
}

// TestMetal2ResetBackupRestoreWipesOnce is K-110 (b0b95a4): a microVM on machine 2 with a file
// in it. A reset taken back at once wipes nothing. A reset, a backup taken while it is pending,
// the reset applied (the disk made afresh: once), a new file; then machine 1 restored from that
// backup, whose silo still asks for that reset: machine 2 says it was applied here already, the
// disk is the same logical volume and the new file is there (not wiped twice).
//
// Listens on nothing outside.
func TestMetal2ResetBackupRestoreWipesOnce(t *testing.T) {
	p := metal2(t)
	r := newRestorer(t, p)
	c := p.c1
	ns := "resetonce2"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080) + on(metalHost2))
	c.waitRunning(ns, 20*time.Minute, "vm")
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "vm", UID: c.silo(ns, "vm").UID})
	lvTime := func() string { return strings.TrimSpace(p.c2.mustSh("lvs --noheadings -o lv_time kevaso/" + n.LV)) }
	mark := func(v string) {
		if out, code := c.in(ns, "vm", "echo "+v+" > /root/marker && sync"); code != 0 {
			t.Fatalf("write %s: %d %s", v, code, out)
		}
	}
	mark("one")
	t0 := lvTime()
	since := strings.TrimSpace(p.c2.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))

	// 1. A reset taken back at once.
	old := c.silo(ns, "vm").Spec.Reset
	c.must("", "reset", "silo", "vm", "-n", ns)
	for i := 0; ; i++ {
		var cur v1.Silo
		if err := json.Unmarshal([]byte(c.must("", "get", "silo", "vm", "-n", ns, "-o", "json")), &cur); err != nil {
			t.Fatal(err)
		}
		cur.Spec.Reset = old
		b, _ := json.Marshal(cur)
		if _, code := c.kvo(string(b), "apply", "-f", "-"); code == 0 {
			break
		}
		if i > 20 {
			t.Fatal("couldn't take the reset back")
		}
	}
	c.waitRunning(ns, 10*time.Minute, "vm")
	if now := lvTime(); now != t0 {
		t.Errorf("a reset taken back wiped the disk: %s → %s", t0, now)
	}
	got, _ := c.in(ns, "vm", "cat /root/marker 2>&1")
	c.expect("taken back: its file is there", got, "one")

	// 2. A reset, a backup while it is pending, the reset applied.
	c.must("", "reset", "silo", "vm", "-n", ns)
	pending := c.silo(ns, "vm")
	r.backup()
	t.Logf("backed up with spec.reset %q, Ready %v", pending.Spec.Reset, meta.FindCondition(c.silo(ns, "vm").Status.Conditions, "Ready"))
	c.eventually("the reset applied: a new root disk", 10*time.Minute, func() (bool, string) { now := lvTime(); return now != t0, now })
	c.waitRunning(ns, 10*time.Minute, "vm")
	t1 := lvTime()
	got, _ = c.in(ns, "vm", "cat /root/marker 2>&1")
	if strings.TrimSpace(got) == "one" {
		t.Errorf("the reset kept the old file: the disk wasn't made afresh")
	}
	mark("two")

	// 3. Restored from the backup that still asks for the reset.
	r.restore()
	c.eventually("the restored silo runs", 10*time.Minute, func() (bool, string) {
		s := c.silo(ns, "vm")
		return s.Status.Phase == "Running", s.Status.Phase
	})
	time.Sleep(30 * time.Second) // a resync or two on machine 2
	if now := lvTime(); now != t1 {
		t.Errorf("the restore wiped the disk a second time: %s → %s", t1, now)
	}
	got, _ = c.in(ns, "vm", "cat /root/marker 2>&1")
	c.expect("after the restore: the new file is there", got, "two")
	j := p.c2.mustSh("journalctl -u kevasod --no-pager --since '" + since + "' | grep '" + ns + "/vm' | grep -E 'reset|applied|afresh|kept' | tail -10")
	t.Logf("machine 2's journal:\n%s", j)
	if !strings.Contains(j, "was applied here already") {
		t.Errorf("machine 2 didn't say the reset was applied here already")
	}
	if u := meta.FindCondition(c.silo(ns, "vm").Status.Conditions, "Updated"); u == nil || u.Reason != "AlreadyApplied" {
		t.Logf("Updated: %v", u)
	}
}
