package kvoadm

import (
	"context"
	"debug/macho"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/sshboot"
)

// A Mac worker (research E038-E042, kevaso-idealization parked.md §7): kevasod runs there under
// launchd as root, like on Linux (the mesh's utun needs it), and runs tart as the Mac's user
// (--tart-user: Tart's images and VMs are a user's, and Virtualization.framework runs as one),
// with the tart runtime and nothing else. The control plane stays on Linux.
//
// Not there on a Mac: SSH hardening, and the install record (kvoadm reset removes Kevaso's own
// paths, daemons and silos by a fixed list, see macops.go).

// MacLabel is the launchd label of kevasod on a Mac.
const MacLabel = "com.kevaso.kevasod"

// MacLog is where launchd sends kevasod's output.
const MacLog = "/var/log/kevasod.log"

// checkScriptDarwin is checkScript for a Mac: what kvoadm needs to know, one KEY=VALUE per line.
// It only reads. kvoadm runs it with sudo -n, so uid and user are the account that logged in
// (sudo's SUDO_UID and SUDO_USER), not root; only a direct root login reports uid 0.
const checkScriptDarwin = `echo "os=$(sw_vers -productName) $(sw_vers -productVersion)"
echo "os_id=macos"
echo "os_version=$(sw_vers -productVersion | cut -d. -f1)"
echo "arch=$(uname -m)"
echo "uid=${SUDO_UID:-$(id -u)}"
echo "user=${SUDO_USER:-$(id -un)}"
command -v launchctl >/dev/null && echo launchd=yes || echo launchd=no
for p in /opt/homebrew/opt/openssl@3/bin/openssl /opt/homebrew/bin/openssl /usr/local/opt/openssl@3/bin/openssl /usr/local/bin/openssl; do
  if [ -x "$p" ] && "$p" version | grep -q '^OpenSSL'; then echo openssl3=yes; break; fi
done
export PATH=/opt/homebrew/bin:/usr/local/bin:$PATH
if command -v tart >/dev/null; then echo "tart=$(tart --version 2>/dev/null | head -n 1)"; else echo tart=no; fi
command -v softnet >/dev/null && echo softnet=yes || echo softnet=no
echo "cpus=$(sysctl -n hw.ncpu)"
echo "memory_mib=$(( $(sysctl -n hw.memsize) / 1048576 ))"
echo "disk_free_gib=$(df -g / 2>/dev/null | awk 'NR==2 {print $4}')"
echo "password_login=$(sshd -T 2>/dev/null | awk '/^passwordauthentication/ {print $2}')"
launchctl print system/` + MacLabel + ` >/dev/null 2>&1 && echo kevasod=running || echo kevasod=absent
(netstat -an -p tcp 2>/dev/null | awk '$6=="LISTEN" {print $4}' | grep -q '[.:]6443$') && echo port_6443=taken || echo port_6443=free
`

// assessMac is AssessWith for a Mac: facts in, findings out. Pure.
func assessMac(facts map[string]string, sup Supported) []CheckResult {
	var out []CheckResult
	add := func(level, what, found, note string) {
		out = append(out, CheckResult{What: what, Found: found, Note: note, Level: level})
	}
	add("ok", "operating system", facts["os"], "")
	if v := atoiOr(facts["os_version"], 0); v < 13 {
		add("fail", "macOS version", facts["os_version"], "macOS silos need Virtualization.framework's macOS guests: macOS 13 or later")
	}
	switch facts["arch"] {
	case "arm64":
		add("ok", "CPU", "arm64", "Apple Silicon: build kevasod with GOOS=darwin GOARCH=arm64")
	default:
		add("fail", "CPU", facts["arch"], "macOS silos run on Apple Silicon only")
	}
	if facts["uid"] == "0" {
		add("fail", "account", "root", "log in as the Mac's own user (with passwordless sudo): tart runs as that user, kevasod as root")
	} else {
		add("ok", "account", "uid "+facts["uid"]+" ("+facts["user"]+")", "tart runs as this user; kvoadm runs every change with sudo -n")
	}
	if facts["launchd"] == "yes" {
		add("ok", "launchd", "yes", "")
	} else {
		add("fail", "launchd", "missing", "kevasod runs as a launchd daemon")
	}
	if facts["openssl3"] == "yes" {
		add("ok", "openssl", "3 or later", "")
	} else {
		add("fail", "openssl", "LibreSSL only", "kvoadm checks kevasod's signature with an OpenSSL that reads ed25519: brew install openssl@3")
	}
	if t := facts["tart"]; t == "" || t == "no" {
		add("fail", "tart", "not installed", "brew install openai/tools/tart (Tart is licensed FSL-1.1-ALv2; Kevaso only runs the program)")
	} else {
		add("ok", "tart", t, "macOS silos: at most two running per Mac (Apple's licence)")
	}
	if facts["softnet"] == "yes" {
		add("ok", "softnet", "installed", "needs a sudoers rule for that binary, or kevasod's --tart-softnet=false")
	} else {
		add("warn", "softnet", "not installed", "without it silos reach each other and your LAN: brew install openai/tools/softnet")
	}
	cpus, mem, disk := atoiOr(facts["cpus"], 0), atoiOr(facts["memory_mib"], 0), atoiOr(facts["disk_free_gib"], 0)
	level := "ok"
	if mem < 16*1024 {
		level = "warn"
	}
	add(level, "size", fmt.Sprintf("%d CPUs, %d MiB memory, %d GiB free", cpus, mem, disk), "a macOS silo is 4 CPUs and 8 GiB by default, and its image is 25-70 GB: plan 150 GB free")
	switch facts["password_login"] {
	case "yes":
		add("warn", "SSH password login", "on", "anyone can try passwords: use keys")
	case "no":
		add("ok", "SSH password login", "off", "")
	}
	if facts["kevasod"] == "running" {
		add("warn", "kevasod", "already running", "host add replaces its launchd daemon")
	}
	if facts["port_6443"] == "taken" && facts["kevasod"] != "running" {
		add("fail", "port 6443", "taken", "the API listens on 6443: something else already does")
	}
	add("warn", "macOS worker", "new", "tested by hand on one Mac, not yet by the end-to-end suite; "+supportNote(sup))
	return out
}

func supportNote(sup Supported) string {
	return "kevasod's supported list (" + sup.From + ") names Linux systems only"
}

func atoiOr(s string, d int) int {
	n := 0
	if s == "" {
		return d
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return d
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// BinaryTarget says what a kevasod binary is built for: the OS (linux, darwin) and the CPU in
// `uname -m` terms.
func BinaryTarget(path string) (goos, arch string, err error) {
	if a, err := ElfArch(path); err == nil {
		return "linux", a, nil
	}
	f, err := macho.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("%s: not a Linux or macOS binary", path)
	}
	defer func() { _ = f.Close() }()
	switch f.Cpu {
	case macho.CpuArm64:
		return "darwin", "arm64", nil
	case macho.CpuAmd64:
		return "darwin", "x86_64", nil
	}
	return "", "", fmt.Errorf("%s: unsupported macOS CPU %v", path, f.Cpu)
}

// MacWorkerArgs are kevasod's arguments for a Mac worker: tart runs as user.
func MacWorkerArgs(o HostAddOptions, server, user string) []string {
	args := []string{"worker", "--name", o.Name, "--server", server, "--tart-user", user}
	for _, r := range o.Runtimes {
		args = append(args, "--runtime", r)
	}
	return args
}

// MacWorkerPlist is the launchd daemon of a Mac worker: kevasod, as root, restarted if it dies,
// logging to MacLog, with Homebrew's folders on its PATH (tart lives there). Pure.
func MacWorkerPlist(args []string) string { return macPlist(MacLabel, MacLog, args) }

// MacFenceLabel is the launchd label of the fence (kevasod fence-watch), a daemon of its own that
// keeps running when kevasod stops: that is when it is needed (as kevaso-fence.service on Linux).
const MacFenceLabel = "com.kevaso.fence"

// MacFenceLog is where launchd sends the fence's output.
const MacFenceLog = "/var/log/kevaso-fence.log"

// MacFenceArgs are the fence's arguments on a Mac: the runtimes it may stop silos of, and the user
// tart runs as.
func MacFenceArgs(runtimes []string, user string) []string {
	args := []string{"fence-watch", "--fence-after", fence.DefaultAfter.String(), "--tart-user", user}
	for _, r := range runtimes {
		args = append(args, "--runtime", r)
	}
	return args
}

// MacFencePlist is the fence's launchd daemon. Pure.
func MacFencePlist(args []string) string { return macPlist(MacFenceLabel, MacFenceLog, args) }

func macPlist(label, logPath string, args []string) string {
	var b strings.Builder
	esc := func(s string) string {
		var x strings.Builder
		_ = xml.EscapeText(&x, []byte(s))
		return x.String()
	}
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + sshboot.InstallDir + `/kevasod</string>
`)
	for _, a := range args {
		b.WriteString("\t\t<string>" + esc(a) + "</string>\n")
	}
	b.WriteString(`	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key><string>/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ThrottleInterval</key><integer>2</integer>
	<key>StandardOutPath</key><string>` + logPath + `</string>
	<key>StandardErrorPath</key><string>` + logPath + `</string>
</dict>
</plist>
`)
	return b.String()
}

// macRefusals are the options of host add that only mean something on Linux, named when a Mac is
// asked for them.
func macRefusals(o HostAddOptions) []string {
	var out []string
	if o.LoopStorage != "" {
		out = append(out, "--loop-storage (silo disks are APFS clones on a Mac)")
	}
	if o.StorageDevice != "" {
		out = append(out, "--storage-device")
	}
	if o.EgressExtraCA != "" {
		out = append(out, "--egress-extra-ca (the egress gate is Linux only)")
	}
	if o.GatewayScope != "" {
		out = append(out, "--openshell-gateway-scope")
	}
	for _, r := range o.Runtimes {
		if r != "tart" {
			out = append(out, "--runtime "+r+" (a Mac runs the tart runtime only)")
		}
	}
	if o.Install != "" && o.Install != "worker" {
		out = append(out, "--install "+o.Install+" (a Mac is a worker; control planes run on Linux)")
	}
	return out
}

// installMacWorker puts the worker on a Mac: the launchd daemon, which runs kevasod as root and
// tart as the user kvoadm logged in as.
func installMacWorker(ctx context.Context, conn *sshboot.Conn, o HostAddOptions, server string, say func(string, ...any)) error {
	user := o.User
	if user == "" || user == "root" {
		return errors.New("log in to the Mac as its own user (with passwordless sudo), not root: tart runs as that user")
	}
	// The fence first, as on Linux: a silo that opted into stopping when its host loses the control
	// plane is armed only while the fence runs.
	if err := conn.InstallLaunchDaemon(ctx, MacFenceLabel, []byte(MacFencePlist(MacFenceArgs(o.Runtimes, user)))); err != nil {
		return err
	}
	if err := conn.InstallLaunchDaemon(ctx, MacLabel, []byte(MacWorkerPlist(MacWorkerArgs(o, server, user)))); err != nil {
		return err
	}
	say("worker started (launchd %s: kevasod as root, tart as %s), joining %s; fence started (%s)", MacLabel, user, server, MacFenceLabel)
	return nil
}
