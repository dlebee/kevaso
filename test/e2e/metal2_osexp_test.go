//go:build metal

package e2e

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/openshell"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
)

// TestMetal2OpenShellExperiment is openshell.md's item 5 on machine 1, both drivers, without the
// reboot steps (those end the long soak: held for the reset gate). It records, and asserts only
// what the branch promises: after kevasod's own stop the unit is inactive and not enabled, and
// when kevasod starts the silo again its start claim comes before the gateway's start. Each window
// with kevasod stopped is kept near a minute (machine 1 is the control plane, and the soak's
// opted-in silo stops after 2m without it).
//
// Listens on nothing outside.
func TestMetal2OpenShellExperiment(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "osexp2"
	c.namespace(ns)
	enable := func(rts ...string) {
		args := []string{"host", "enable-worker", c.cfg.SSHTarget(), "--ssh-port", strconv.Itoa(c.cfg.Port), "--ssh-key", c.cfg.KeyFile,
			"--host-key", c.cfg.HostKey, "--loop-storage", metalLoop}
		for _, r := range rts {
			args = append(args, "--runtime", r)
		}
		var o bytes.Buffer
		if code := kvoadm.Run(c.ctx, args, strings.NewReader(""), &o, &o); code != 0 {
			t.Fatalf("enable-worker %v: exit %d\n%s", rts, code, o.String())
		}
		c.eventually("the API back", 3*time.Minute, func() (bool, string) { out, code := c.kvo("", "get", "hosts"); return code == 0, out })
	}
	enable("cloud-hypervisor", "docker", "openshell", "openshell-container")
	t.Cleanup(func() { enable("cloud-hypervisor", "docker") })
	c.runtimeReady("openshell", 25*time.Minute)
	c.runtimeReady("openshell-container", 25*time.Minute)
	sil := func(name, rt string) string {
		return "---\napiVersion: kevaso/v1\nkind: Silo\nmetadata: { name: " + name + ", namespace: " + ns + " }\nspec:\n  runtime: " + rt +
			"\n  container: { image: ubuntu-24.04 }\n  resources: { cpu: 1, memory: 1Gi }\n" + on(metalHost)
	}
	c.apply(sil("osvm", "openshell") + sil("osct", "openshell-container"))
	c.waitRunning(ns, 35*time.Minute, "osvm", "osct")

	type sb struct{ name, driver, unit, sandbox, key string }
	var boxes []sb
	for name, driver := range map[string]string{"osvm": openshell.DriverVM, "osct": openshell.DriverDocker} {
		id := kri.ID{Namespace: ns, Name: name, UID: c.silo(ns, name).UID}
		key := openshell.GatewayKey(driver, openshell.ScopeNamespace, id)
		boxes = append(boxes, sb{name, driver, openshell.Gateway{Key: key}.Unit(), openshell.SandboxName(id), key})
	}
	cli := func(b sb, args string) string {
		d := "/var/lib/kevaso-openshell/gw/" + b.key
		return "env HOME=" + d + " XDG_CONFIG_HOME=" + d + "/.config XDG_STATE_HOME=" + d + "/.local/state XDG_DATA_HOME=" + d + "/.local/share OPENSHELL_GATEWAY=kv-" + b.key + " NO_COLOR=1 openshell " + args
	}
	look := func(step string) {
		for _, b := range boxes {
			script := "echo \"unit: $(systemctl is-active " + b.unit + ") $(systemctl is-enabled " + b.unit + " 2>&1)\"; echo '-- sandbox list:'; " + cli(b, "sandbox list -o json") + " 2>&1 | head -c 1500; echo"
			if b.driver == openshell.DriverVM {
				script += "; echo '-- cgroup:'; for p in $(systemd-cgls --no-pager -u " + b.unit + " 2>/dev/null | grep -oE '[0-9]+ ' ); do ps -o pid=,args= -p $p 2>/dev/null | cut -c1-200; done"
			} else {
				script += "; echo '-- docker:'; docker ps -a --format '{{.Names}} {{.Status}} {{.Labels}}' | grep -- '" + b.sandbox + "' | cut -c1-220; " +
					"for c in $(docker ps -aq --filter name=" + b.sandbox + "); do echo \"restart policy $(docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' $c)\"; done"
			}
			out, _ := p.c1.sh(script)
			t.Logf("LOOK %s, %s (%s, unit %s, sandbox %s):\n%s", step, b.name, b.driver, b.unit, b.sandbox, out)
		}
	}
	unitStarted := func(b sb) string {
		return strings.TrimSpace(p.c1.mustSh("systemctl show -p ActiveEnterTimestamp --value " + b.unit))
	}
	claimAfterStart := func(step string) {
		c.waitRunning(ns, 10*time.Minute, "osvm", "osct")
		for _, b := range boxes {
			claim := claimTime(c.silo(ns, b.name))
			started := unitStarted(b)
			ct, err1 := time.Parse(time.RFC3339Nano, claim)
			ut, err2 := time.Parse("Mon 2006-01-02 15:04:05 MST", started)
			t.Logf("%s, %s: start claim at %s, gateway unit started %s", step, b.name, claim, started)
			if err1 == nil && err2 == nil && ut.Add(time.Second).Before(ct) {
				t.Errorf("%s, %s: the gateway started (%s) before the start claim (%s)", step, b.name, started, claim)
			}
		}
	}
	look("A1 running")
	// A: the sandbox stopped as Kevaso stops it.
	p.c1.mustSh("systemctl stop kevasod")
	for _, b := range boxes {
		out, _ := p.c1.sh(cli(b, "sandbox stop "+b.sandbox) + " 2>&1; systemctl stop " + b.unit)
		t.Logf("A2 %s: %s", b.name, out)
	}
	look("A2 stopped (kevasod down)")
	for _, b := range boxes {
		if st := strings.TrimSpace(p.c1.mustSh("systemctl is-active " + b.unit + " || true; systemctl is-enabled " + b.unit + " 2>&1 || true")); !strings.HasPrefix(st, "inactive") || strings.Contains(st, "enabled") && !strings.Contains(st, "disabled") {
			t.Errorf("A2 %s: unit %q, want inactive and not enabled", b.name, st)
		}
		p.c1.mustSh("systemctl start " + b.unit)
	}
	time.Sleep(40 * time.Second)
	look("A3 gateway started again, kevasod down")
	for _, b := range boxes {
		p.c1.mustSh("systemctl stop " + b.unit)
	}
	p.c1.mustSh("systemctl start kevasod")
	claimAfterStart("A6")
	look("A6 kevasod back")
	// B: the sandbox left running, kevasod stopped, the gateway restarted.
	p.c1.mustSh("systemctl stop kevasod")
	look("B2 kevasod down, sandbox running")
	for _, b := range boxes {
		p.c1.mustSh("systemctl restart " + b.unit)
	}
	time.Sleep(40 * time.Second)
	look("B3 gateway restarted, kevasod down")
	p.c1.mustSh("systemctl start kevasod")
	claimAfterStart("B6")
	look("B6 kevasod back")
	// The CLI's own words, for exact handling.
	b := boxes[0]
	words := p.c1.mustSh("echo '-- sandbox get (missing):'; " + cli(b, "sandbox get kv-nosuchsandbox -o json") + " 2>&1 | head -3; " +
		"echo '-- an unknown gateway:'; " + strings.Replace(cli(b, "sandbox list -o json"), "OPENSHELL_GATEWAY=kv-"+b.key, "OPENSHELL_GATEWAY=kv-nosuchgateway", 1) + " 2>&1 | head -3; " +
		"echo '-- profile delete (missing):'; " + cli(b, "profile delete kv-nosuchprofile") + " 2>&1 | head -3; " +
		"echo '-- provider delete (missing):'; " + cli(b, "provider delete kv-nosuchprovider") + " 2>&1 | head -3; true")
	t.Logf("CLI WORDS:\n%s", words)
}
