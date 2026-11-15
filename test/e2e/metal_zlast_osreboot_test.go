//go:build metal

package e2e

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/openshell"
	"kevaso.com/core/sdk/kri"
)

// TestMetalOpenShellReboot is openshell.md item 5's reboot (B4, B6) on one machine, both drivers,
// two silos on each gateway: the machine rebooted with them running. Looked at as soon as it
// answers: each gateway unit isn't enabled; then, as kevasod starts them, each silo's first start
// claim comes before its gateway's start (systemd's time, machine's clock), and all four run
// again. Each step's look (units, sandbox lists, Docker containers and their restart policy) is
// logged.
//
// Listens on nothing outside. It reboots the machine: run it alone or last.
func TestMetalOpenShellReboot(t *testing.T) {
	c := metal(t)
	ns := "osboot"
	c.namespace(ns)
	c.enableWorker("cloud-hypervisor", "docker", "openshell", "openshell-container")
	t.Cleanup(func() { c.enableWorker("cloud-hypervisor", "docker") })
	c.runtimeReady("openshell", 25*time.Minute)
	c.runtimeReady("openshell-container", 25*time.Minute)
	sil := func(name, rt string) string {
		return "---\napiVersion: kevaso/v1\nkind: Silo\nmetadata: { name: " + name + ", namespace: " + ns + " }\nspec:\n  runtime: " + rt +
			"\n  container: { image: ubuntu-24.04 }\n  resources: { cpu: 1, memory: 1Gi }\n"
	}
	names := map[string]string{"vma": openshell.DriverVM, "vmb": openshell.DriverVM, "cta": openshell.DriverDocker, "ctb": openshell.DriverDocker}
	c.apply(sil("vma", "openshell") + sil("vmb", "openshell") + sil("cta", "openshell-container") + sil("ctb", "openshell-container"))
	c.waitRunning(ns, 35*time.Minute, "vma", "vmb", "cta", "ctb")
	type sb struct{ name, driver, unit, sandbox, key string }
	var boxes []sb
	units := map[string]bool{}
	for name, driver := range names {
		id := kri.ID{Namespace: ns, Name: name, UID: c.silo(ns, name).UID}
		key := openshell.GatewayKey(driver, openshell.ScopeNamespace, id)
		b := sb{name, driver, openshell.Gateway{Key: key}.Unit(), openshell.SandboxName(id), key}
		boxes = append(boxes, b)
		units[b.unit] = true
	}
	if len(units) != 2 {
		t.Fatalf("%d gateway units for two drivers: the silos don't share their gateway", len(units))
	}
	cli := func(b sb, args string) string {
		d := "/var/lib/kevaso-openshell/gw/" + b.key
		return "env HOME=" + d + " XDG_CONFIG_HOME=" + d + "/.config XDG_STATE_HOME=" + d + "/.local/state XDG_DATA_HOME=" + d + "/.local/share OPENSHELL_GATEWAY=kv-" + b.key + " NO_COLOR=1 openshell " + args
	}
	look := func(step string) {
		for u := range units {
			out, _ := c.sh("echo \"unit " + u + ": $(systemctl is-active " + u + ") $(systemctl is-enabled " + u + " 2>&1)\"")
			t.Logf("LOOK %s: %s", step, strings.TrimSpace(out))
		}
		for _, b := range boxes {
			script := "echo '-- sandbox list:'; " + cli(b, "sandbox list -o json") + " 2>&1 | head -c 1200; echo"
			if b.driver == openshell.DriverDocker {
				script += "; docker ps -a --format '{{.Names}} {{.Status}}' | grep -- '" + b.sandbox + "' | cut -c1-160; " +
					"for x in $(docker ps -aq --filter name=" + b.sandbox + "); do docker inspect -f '{{.Name}} restart={{.HostConfig.RestartPolicy.Name}}' $x; done"
			} else {
				script += "; ps -eo pid,args | grep -- '[" + b.sandbox[:1] + "]" + b.sandbox[1:] + "' | cut -c1-160"
			}
			out, _ := c.sh(script)
			t.Logf("LOOK %s, %s (%s):\n%s", step, b.name, b.driver, out)
		}
	}
	look("before the reboot")
	bootID := strings.TrimSpace(c.mustSh("cat /proc/sys/kernel/random/boot_id"))
	_, _ = c.sh("nohup sh -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 &")
	_ = c.d.Close()
	time.Sleep(20 * time.Second)
	c.eventually("the machine is back", 15*time.Minute, func() (bool, string) {
		out, err := c.sh("cat /proc/sys/kernel/random/boot_id")
		if err != nil {
			_ = c.d.Close()
			return false, err.Error()
		}
		return strings.TrimSpace(out) != bootID, "same boot"
	})
	for u := range units {
		if st := strings.TrimSpace(c.mustSh("systemctl is-enabled " + u + " 2>&1 || true")); st == "enabled" {
			t.Errorf("B4: gateway unit %s is enabled: it starts at boot with no claim", u)
		}
	}
	look("B4 right after the boot")
	c.eventually("the API answers", 5*time.Minute, func() (bool, string) { out, code := c.kvo("", "get", "hosts"); return code == 0, out })
	first := map[string]string{}
	deadline := time.Now().Add(20 * time.Minute)
	for {
		done := true
		for _, b := range boxes {
			s := c.silo(ns, b.name)
			if at := claimTime(s); at != "" && first[b.name] == "" {
				first[b.name] = at
			}
			done = done && s.Status.Phase == "Running"
		}
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("B6: never all four running after the boot")
		}
		time.Sleep(time.Second)
	}
	for _, b := range boxes {
		started := strings.TrimSpace(c.mustSh("systemctl show -p ActiveEnterTimestamp --value " + b.unit))
		ct, err1 := time.Parse(time.RFC3339Nano, first[b.name])
		ut, err2 := time.Parse("Mon 2006-01-02 15:04:05 MST", started)
		t.Logf("B6 %s: first claim seen %s; its gateway started %s", b.name, first[b.name], started)
		if err1 == nil && err2 == nil && ut.Add(time.Second).Before(ct) && first[b.name] != "" {
			t.Logf("B6 %s: its gateway started before this silo's first claim seen (a neighbour's claim may have started it)", b.name)
		}
	}
	// The gateway's start must follow some claim of its own silos.
	for u := range units {
		started := strings.TrimSpace(c.mustSh("systemctl show -p ActiveEnterTimestamp --value " + u))
		ut, err := time.Parse("Mon 2006-01-02 15:04:05 MST", started)
		earliest := time.Time{}
		for _, b := range boxes {
			if b.unit != u {
				continue
			}
			if ct, err := time.Parse(time.RFC3339Nano, first[b.name]); err == nil && (earliest.IsZero() || ct.Before(earliest)) {
				earliest = ct
			}
		}
		if err == nil && !earliest.IsZero() && ut.Add(time.Second).Before(earliest) {
			t.Errorf("B6: gateway %s started %s, before any of its silos' claims (%s)", u, started, earliest.Format(time.RFC3339Nano))
		}
	}
	look("B6 all running again")
	for _, b := range boxes {
		c.must("", "delete", "silo", b.name, "-n", ns)
	}
	c.eventually("their gateways are gone", 5*time.Minute, func() (bool, string) {
		out := strings.TrimSpace(c.mustSh("systemctl list-units --all --plain --no-legend 'kevaso-openshell-*' | wc -l"))
		return out == "0", out + " gateway units"
	})
}
