package kvoadm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/sshboot"
)

// What kvoadm upgrade, host reconnect and reset do on a Mac, where kevasod is a launchd daemon
// (macos.go) and there is no systemd, no install record and no storage to wipe.

// MacUpgradeRestart starts the new binary: the fence first (an old watcher reads the new record its
// own way), then kevasod.
const MacUpgradeRestart = "launchctl kickstart -k system/" + MacFenceLabel + " 2>/dev/null; launchctl kickstart -k system/" + MacLabel

var serverArg = regexp.MustCompile(`(<string>--server</string>\s*<string>)([^<]*)(</string>)`)

// RepointMacPlist points a Mac worker's launchd plist at another control plane: --server's value
// is replaced. It reports whether anything changed. Pure.
func RepointMacPlist(plist, server string) (string, bool, error) {
	m := serverArg.FindStringSubmatch(plist)
	if m == nil {
		return "", false, errors.New("no --server in the plist: is this a worker?")
	}
	if m[2] == server {
		return plist, false, nil
	}
	return serverArg.ReplaceAllString(plist, "${1}"+strings.ReplaceAll(server, "$", "$$")+"${3}"), true, nil
}

var plistName = regexp.MustCompile(`<string>--name</string>\s*<string>([^<]*)</string>`)

// MacPlistName is the host's name in its plist ("" when there is none).
func MacPlistName(plist string) string {
	if m := plistName.FindStringSubmatch(plist); m != nil {
		return m[1]
	}
	return ""
}

// macTart runs tart as user, from a root shell: the line every Mac script here uses.
func macTart(user, args string) string {
	return "sudo -n -H -u " + sshboot.Quote(user) + " env PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin tart " + args
}

// MacInspectScript looks at a Mac (it only reads): how many silos' VMs (named kv-…) Tart holds for
// user, and whether kevasod's daemon is loaded.
func MacInspectScript(user string) string {
	return `n=$(` + macTart(user, "list --format json 2>/dev/null") + ` | grep -o '"Name" *: *"kv-[^"]*"' | wc -l | tr -d ' ')
echo "silos=$n"
launchctl print system/` + MacLabel + ` >/dev/null 2>&1 && echo "daemon=yes" || echo "daemon=no"
[ -e /usr/local/bin/kevasod ] && echo "binary=yes" || echo "binary=no"
`
}

// MacRemoveScript takes Kevaso off a Mac: the daemons, the silos' VMs (only with silos true), the
// binary, the logs, the config and the data. Tart's own images stay (they are the operator's).
func MacRemoveScript(user string, silos bool) string {
	s := "launchctl bootout system/" + MacFenceLabel + " 2>/dev/null; launchctl bootout system/" + MacLabel + " 2>/dev/null; sleep 1\n"
	if silos {
		s += `for v in $(` + macTart(user, "list --format json 2>/dev/null") + ` | grep -o '"Name" *: *"kv-[^"]*"' | sed 's/.*"\(kv-[^"]*\)"/\1/'); do ` +
			macTart(user, `stop "$v" --timeout 0 2>/dev/null`) + `; ` + macTart(user, `delete "$v"`) + `; done` + "\n"
	}
	s += "rm -f " + sshboot.LaunchDaemonsDir + "/" + MacLabel + ".plist " + sshboot.LaunchDaemonsDir + "/" + MacFenceLabel + ".plist " +
		sshboot.InstallDir + "/kevasod " + MacLog + " " + MacFenceLog + "\n" +
		"rm -rf /etc/kevaso /var/lib/kevaso /var/run/kevaso /var/run/kevaso-fence /var/run/wireguard\n"
	return s
}

// macInspection is what MacInspectScript found.
type macInspection struct {
	Silos          int
	Daemon, Binary bool
}

func parseMacInspection(raw string) macInspection {
	var m macInspection
	for _, l := range strings.Split(raw, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "silos":
			m.Silos = atoiOr(v, 0)
		case "daemon":
			m.Daemon = v == "yes"
		case "binary":
			m.Binary = v == "yes"
		}
	}
	return m
}

// ErrMacSilos: the Mac still holds silos; reset removes their VMs only with --force.
var ErrMacSilos = errors.New("silos are on this Mac")

// runMacReset is kvoadm reset for a Mac.
func runMacReset(ctx context.Context, h hostRunner, o ResetOptions, in *bufio.Reader, out io.Writer) error {
	user := o.User
	if user == "" || user == "root" {
		return errors.New("log in to the Mac as its own user: tart's silos are that user's")
	}
	raw, err := h.Run(ctx, MacInspectScript(user), nil)
	if err != nil {
		return fmt.Errorf("looking at the Mac: %w", err)
	}
	insp := parseMacInspection(string(raw))
	if insp.Silos > 0 && !o.Force {
		return fmt.Errorf("%w: %d macOS silo VM(s) (kv-…). Delete them with kvo delete silo, or pass --force to remove their VMs and what is on them", ErrMacSilos, insp.Silos)
	}
	_, _ = fmt.Fprintf(out, "\nkvoadm reset %s will:\n  - stop and remove kevasod's launchd daemons (%s, %s)\n  - remove /usr/local/bin/kevasod, its logs, /etc/kevaso and /var/lib/kevaso\n", o.Address, MacLabel, MacFenceLabel)
	if insp.Silos > 0 {
		_, _ = fmt.Fprintf(out, "  - delete %d macOS silo VM(s), and the data on them (--force)\n", insp.Silos)
	}
	_, _ = fmt.Fprintf(out, "\nIt never touches Tart or its images, SSH, or anything outside Kevaso's paths.\n")
	if o.DryRun {
		return ErrDryRun
	}
	if !o.Yes {
		_, _ = fmt.Fprint(out, "Go ahead? [y/N] ")
		ans, _ := in.ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			return errors.New("not confirmed: nothing was changed")
		}
	}
	if _, err := h.Run(ctx, MacRemoveScript(user, insp.Silos > 0), nil); err != nil {
		return fmt.Errorf("removing Kevaso from the Mac: %w", err)
	}
	left, err := h.Run(ctx, MacInspectScript(user), nil)
	if err != nil {
		return err
	}
	if after := parseMacInspection(string(left)); after.Daemon || after.Binary || after.Silos > 0 {
		return fmt.Errorf("left on the Mac after the reset: daemon %v, binary %v, silo VMs %d", after.Daemon, after.Binary, after.Silos)
	}
	_, _ = fmt.Fprintln(out, "✓ Kevaso is off this Mac")
	return nil
}

// reconnectMac points a Mac worker at server (kvoadm host reconnect).
func reconnectMac(ctx context.Context, conn *sshboot.Conn, server string, c *client.Client) (string, error) {
	path := sshboot.LaunchDaemonsDir + "/" + MacLabel + ".plist"
	plist, err := conn.Run(ctx, "cat "+path, nil)
	if err != nil {
		return "", err
	}
	name := MacPlistName(string(plist))
	updated, changed, err := RepointMacPlist(string(plist), server)
	if err != nil {
		return name, err
	}
	since := time.Now()
	// Already repointed (an earlier reconnect got this far) but not loaded: launch it anyway, or
	// a second try waits for a daemon nothing started.
	_, notLoaded := conn.Run(ctx, "launchctl print system/"+sshboot.Quote(MacLabel)+" >/dev/null 2>&1", nil)
	if changed || notLoaded != nil {
		if err := conn.InstallLaunchDaemon(ctx, MacLabel, []byte(updated)); err != nil {
			return name, err
		}
	}
	if err := waitHeartbeat(ctx, c, name, since, 2*time.Minute); err != nil {
		logs, _ := conn.Run(ctx, "tail -n 15 "+MacLog, nil)
		return name, fmt.Errorf("%w\nkevasod on the host:\n%s", err, logs)
	}
	return name, nil
}
