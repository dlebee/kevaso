//go:build metal

package e2e

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
)

// TestMetal2RestoreKeepsWhatItDoesntKnow is §0.7's worker side of a restore, on the machines:
// a backup of the cluster, then a microVM with a volume made on machine 2, then machine 1's
// control plane reset and restored from that backup (kvoadm init --restore: a new history).
// Machine 2 accepts the restored control plane (it isn't held), and the silo the restored
// state doesn't know keeps running there with its volume, listed on its Host (KeptSilos).
// It re-makes machine 1's control plane, so it runs late (before the disk reset).
//
// Listens on nothing outside.
func TestMetal2RestoreKeepsWhatItDoesntKnow(t *testing.T) {
	p := metal2(t)
	if p.recoveryKey == "" {
		t.Skip("needs the cluster this run made (its recovery key): not with KEVASO_METAL_REUSE")
	}
	c := p.c1
	ns := "restore2"
	c.namespace(ns)
	cfg1 := p.m1.cfg
	sshArgs := []string{cfg1.SSHTarget(), "--ssh-port", strconv.Itoa(cfg1.Port), "--ssh-key", cfg1.KeyFile, "--host-key", cfg1.HostKey}
	kvoadmRun := func(stdin string, args ...string) string {
		t.Helper()
		var o bytes.Buffer
		if code := kvoadm.Run(c.ctx, args, strings.NewReader(stdin), &o, &o); code != 0 {
			t.Fatalf("kvoadm %s: exit %d\n%s", args[0], code, metalRedact(o.String()))
		}
		return metalRedact(o.String())
	}
	file := filepath.Join(t.TempDir(), "metal2.kvb")
	t.Log(kvoadmRun("", append(append([]string{"backup"}, sshArgs...), "--output", file)...))

	// After the backup: a microVM with a volume on machine 2.
	c.apply(vmEcho(ns, "late", 8080) + on(metalHost2) + "  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n")
	c.waitRunning(ns, 20*time.Minute, "late")
	if out, code := c.in(ns, "late", "echo kept > /data/marker && sync"); code != 0 {
		t.Fatalf("write: %d %s", code, out)
	}
	s := c.silo(ns, "late")
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: "late", UID: s.UID})
	started := strings.TrimSpace(p.c2.mustSh("systemctl show -p ActiveEnterTimestamp --value " + n.Unit))
	lvs := strings.TrimSpace(p.c2.mustSh("lvs --noheadings -o lv_name kevaso | tr -d ' ' | grep -c '^kv-' || true"))

	// Machine 1's control plane, reset and restored from the backup.
	_ = p.m1.d.Close()
	t.Log(kvoadmRun("", append(append([]string{"reset"}, sshArgs...), "--force", "--yes")...))
	out := kvoadmRun(p.recoveryKey+"\n", append(append([]string{"init"}, sshArgs...), "--kevasod", p.bin, "--no-extra-hardening", "--restore", file,
		"--api-server", "https://"+net.JoinHostPort(cfg1.ExternalIP, "6443"), "--external-ip", cfg1.ExternalIP)...)
	t.Logf("kvoadm init --restore:\n%s", out)
	p.mu.Lock()
	p.m1Worker = false // restored as the system node only
	p.mu.Unlock()

	c.eventually(metalHost2+" is Ready with the restored control plane", 10*time.Minute, func() (bool, string) { return c.hostReady(metalHost2) })
	h := c.hostNamed(metalHost2)
	if b := meta.FindCondition(h.Status.Conditions, agent.ConditionControlPlaneBehind); b != nil && b.Status == meta.ConditionTrue {
		t.Errorf("machine 2 holds after a deliberate restore: %s", b.Message)
	}
	if o, code := c.kvo("", "get", "silo", "late", "-n", ns); code == 0 {
		t.Fatalf("the restored state knows the silo made after the backup: %s", o)
	}
	time.Sleep(time.Minute) // a resync or two on machine 2
	c.expect("machine 2 keeps it running", p.c2.mustSh("systemctl is-active "+n.Unit+" || true"), "active")
	if now := strings.TrimSpace(p.c2.mustSh("systemctl show -p ActiveEnterTimestamp --value " + n.Unit)); now != started {
		t.Errorf("the kept silo restarted: %q → %q", started, now)
	}
	if now := strings.TrimSpace(p.c2.mustSh("lvs --noheadings -o lv_name kevaso | tr -d ' ' | grep -c '^kv-' || true")); now != lvs {
		t.Errorf("machine 2's logical volumes: %s before, %s after (its disk and volume must stay)", lvs, now)
	}
	c.eventually("machine 2 lists it as kept", 3*time.Minute, func() (bool, string) {
		h := c.hostNamed(metalHost2)
		k := meta.FindCondition(h.Status.Conditions, agent.ConditionKeptSilos)
		return k != nil && k.Status == meta.ConditionTrue && strings.Contains(k.Message, ns+"/late"), fmt.Sprint(k)
	})
}
