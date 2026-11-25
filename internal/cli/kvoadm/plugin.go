package kvoadm

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/term"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/names"
	"kevaso.com/core/internal/operators"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/sshboot"
	"kevaso.com/core/sdk/kplugin"
)

// PluginOptions are kvoadm plugin install's flags.
type PluginOptions struct {
	InitOptions
	Name   string
	Binary string
	Side   string // controller (default: on a control plane, serving the API) | node (on a worker)
	// ClusterSecrets are ClusterSecret names this side's unit loads (LoadCredential=NAME: a folder, each key the credential NAME_KEY).
	// Install records the names and copies no value: kevasod writes each one, root only, at
	// the path the unit already names. Repeatable.
	ClusterSecrets []string
	Config         string // a local file: the plugin's settings (not secret)
	// Manifest is the plugin's kevaso-plugin.json (a local file): what each side needs from the
	// host. Without one, a side gets nothing beyond the default (PluginUnit). Needs is this side's.
	Manifest string
	Needs    kplugin.Needs
	// DevicePrefixes are where the manifest says its attached volumes' devices are (K-038), and
	// ManifestText the manifest itself, stored on the host for kevasod to check answers against.
	DevicePrefixes []string
	ManifestText   []byte
	Yes            bool // the operator grants what the manifest asks (needed when it asks for privileges)
}

var pluginName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// PluginUnit is the systemd unit a plugin side runs as. By default: its own dynamic user, no
// capabilities, read-only system, only the network and its own socket folder; its cluster
// secrets through systemd's LoadCredential, readable by it alone. A side whose manifest asks
// for more (o.Needs: root, capabilities, devices, the host's mount namespace, folders to write)
// gets exactly that and keeps every other restriction that still applies. The needs are checked
// again here, where they are granted, whatever produced them (K-039).
func PluginUnit(o PluginOptions) (string, error) {
	if err := checkGrant(o); err != nil {
		return "", err
	}
	n := o.Needs
	bin := "/usr/local/bin/kevaso-plugin-" + o.Name
	exec := bin + " serve --socket " + o.socket()
	if o.Side == "node" {
		exec = bin + " node --socket " + o.socket()
	}
	if o.Config != "" {
		exec += " --config %d/config" // a credential too: the plugin's own user can't read /etc/kevaso
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("[Unit]")
	w("Description=Kevaso plugin %s (%s side)", o.Name, o.side())
	w("After=network-online.target")
	w("Wants=network-online.target")
	w("")
	w("[Service]")
	w("ExecStart=%s", exec)
	if !n.Root {
		w("DynamicUser=yes")
	}
	// Both sides on one host share the folder: neither removes it when it stops.
	w("RuntimeDirectory=%s/%s", strings.TrimPrefix(kplugin.Dir, "/run/"), o.Name)
	w("RuntimeDirectoryMode=0750")
	w("RuntimeDirectoryPreserve=yes")
	names := append([]string(nil), o.ClusterSecrets...)
	sort.Strings(names)
	for _, n := range names { // a folder, one file per key: systemd loads each as the credential NAME_KEY
		w("LoadCredential=%s:%s/%s", n, pluginEtc(o.Name), n)
	}
	if o.Config != "" {
		w("LoadCredential=config:%s/config.json", pluginEtc(o.Name))
	}
	caps := strings.Join(n.Capabilities, " ")
	w("NoNewPrivileges=yes")
	w("CapabilityBoundingSet=%s", caps)
	if n.Root {
		w("AmbientCapabilities=")
	} else {
		w("AmbientCapabilities=%s", caps)
	}
	if len(n.Devices) > 0 || n.HostMounts {
		w("DevicePolicy=closed")
		for _, d := range n.Devices {
			w("DeviceAllow=%s rw", d)
		}
	}
	if !n.HostMounts { // everything that needs a mount namespace of its own
		for _, l := range []string{"ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
			"ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes",
			"ProtectHostname=yes", "ProtectProc=invisible"} {
			w("%s", l)
		}
		if !n.Mounts() {
			// A side that mounts runs a file-system daemon (juicefs), which reads /proc/sys
			// (kernel.osrelease, fs limits) and panics without it.
			w("ProcSubset=pid")
		}
		if len(n.Devices) == 0 {
			w("PrivateDevices=yes")
		}
		if len(n.WritePaths) > 0 {
			// systemd can't make a namespace with a writable folder that isn't there (the unit
			// fails with 226/NAMESPACE): it creates the ones in its own places itself, every start;
			// kvoadm creates the others at install.
			for _, d := range n.WritePaths {
				if kind, rel, ok := systemdDir(d); ok {
					w("%sDirectory=%s", kind, rel)
					w("%sDirectoryMode=0700", kind)
				}
			}
			w("ReadWritePaths=%s", strings.Join(n.WritePaths, " "))
		}
	}
	filter := []string{"SystemCallFilter=@system-service", "SystemCallFilter=~@privileged"}
	if n.Mounts() {
		filter = []string{"SystemCallFilter=@system-service @mount"}
	}
	umask := "0077"
	if n.HostMounts {
		umask = "0022" // the folders it mounts on are entered by others (containers, virtiofsd)
	}
	for _, l := range append([]string{
		"ProtectClock=yes", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", "RestrictNamespaces=yes", "RestrictRealtime=yes",
		"RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes", "SystemCallArchitectures=native",
	}, append(filter, "UMask="+umask, "Restart=always", "RestartSec=2")...) {
		w("%s", l)
	}
	if n.HostMounts {
		// The file-system daemons it started serve mounts the host's silos use: a restart of the
		// plugin must not kill them (it finds its mounts again in the host's mount table).
		w("KillMode=process")
	}
	w("")
	w("[Install]")
	w("WantedBy=multi-user.target")
	return b.String(), nil
}

// checkGrant refuses needs the manifest rules don't allow (a write path that isn't the plugin's
// own folder, …): the same check as reading a manifest, at the place they are granted.
func checkGrant(o PluginOptions) error {
	if !pluginName.MatchString(o.Name) {
		return fmt.Errorf("plugin name %q", o.Name)
	}
	if err := o.Needs.Check(o.Name, o.side()); err != nil {
		return fmt.Errorf("plugin %s: %w", o.Name, err)
	}
	return nil
}

// WritePathScript makes sure write path p is a real folder on the host before the unit grants it:
// no part of it a symlink (systemd would grant where it points), not something else that isn't a
// folder; it is made (0700) only if missing, so an existing folder's mode is never changed. A
// state, cache or log folder of a dynamic-user side is systemd's own symlink into private/: that
// one link is the only one allowed.
func WritePathScript(p string) string {
	q := sshboot.Quote(p)
	private := "''"
	if _, rel, ok := systemdDir(p); ok {
		private = sshboot.Quote("private/" + rel)
	}
	return "p=" + q + "; q=''; IFS=/; set -f; for c in ${p#/}; do q=\"$q/$c\"; " +
		"if [ -L \"$q\" ] && ! { [ \"$q\" = \"$p\" ] && [ \"$(readlink \"$q\")\" = " + private + " ]; }; then " +
		"echo \"$q is a symlink: refusing to grant it\" >&2; exit 1; fi; done; unset IFS; " +
		"if [ -e \"$p\" ] && [ ! -d \"$p\" ]; then echo \"$p is not a folder: refusing to grant it\" >&2; exit 1; fi; " +
		"[ -d \"$p\" ] || install -d -m 0700 -- \"$p\""
}

// systemdDir says which of systemd's own folders (StateDirectory= and the like) p is in, if any,
// and its name there.
func systemdDir(p string) (kind, rel string, ok bool) {
	for base, k := range map[string]string{"/var/lib/": "State", "/var/cache/": "Cache", "/var/log/": "Logs"} {
		if r, found := strings.CutPrefix(p, base); found && r != "" {
			return k, r, true
		}
	}
	return "", "", false
}

// socket is where the side listens (the manifest may name it; kevasod looks in Dir/NAME).
func (o PluginOptions) socket() string {
	sock := o.Needs.Socket
	if sock == "" {
		sock = kplugin.ControllerSocket
		if o.Side == "node" {
			sock = kplugin.NodeSocket
		}
	}
	return kplugin.Dir + "/" + o.Name + "/" + sock
}

// readManifest loads o.Manifest into o.Needs (this side's), checking it's this plugin's.
func readManifest(o *PluginOptions) error {
	if o.Manifest == "" {
		return nil
	}
	b, err := os.ReadFile(o.Manifest)
	if err != nil {
		return err
	}
	m, err := kplugin.ParseManifest(b)
	if err != nil {
		return fmt.Errorf("%s: %w", o.Manifest, err)
	}
	if m.Name != o.Name {
		return fmt.Errorf("%s is plugin %s's manifest, not %s's", o.Manifest, m.Name, o.Name)
	}
	o.Needs = m.Controller
	if o.side() == "node" {
		o.Needs = m.Node
	}
	o.DevicePrefixes, o.ManifestText = m.DevicePrefixes, b
	return nil
}

// grantNeeds shows the operator what the side gets (every folder it may write included), and
// refuses privileges not granted: --yes, or "y" to the question in a terminal.
func grantNeeds(o PluginOptions, in *bufio.Reader, stdin io.Reader, out io.Writer) error {
	if err := checkGrant(o); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "→ plugin %s, %s side:\n", o.Name, o.side())
	for _, l := range o.Needs.Summary() {
		_, _ = fmt.Fprintf(out, "    %s\n", l)
	}
	if len(o.DevicePrefixes) > 0 {
		_, _ = fmt.Fprintf(out, "    volume devices: only under %s (kevasod refuses any other device it answers)\n", strings.Join(o.DevicePrefixes, ", "))
	}
	if !o.Needs.Privileged() || o.Yes {
		return nil
	}
	refused := fmt.Errorf("plugin %s's %s side asks for the privileges above (manifest %s): add --yes to grant them", o.Name, o.side(), o.Manifest)
	if !isTerminal(stdin) {
		return refused
	}
	_, _ = fmt.Fprintf(out, "Grant these to plugin %s's %s side? [y/N] ", o.Name, o.side())
	a, err := readLine(in)
	if err != nil || !slices.Contains([]string{"y", "yes"}, strings.ToLower(strings.TrimSpace(a))) {
		return refused
	}
	return nil
}

// isTerminal: whether the operator can be asked on stdin.
var isTerminal = func(stdin io.Reader) bool {
	f, ok := stdin.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// pluginHardening is every plugin unit's sandbox (operators' too, operator.go).
var pluginHardening = []string{
	"NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=",
	"ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
	"ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes",
	"ProtectClock=yes", "ProtectHostname=yes", "ProtectProc=invisible", "ProcSubset=pid",
	"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", "RestrictNamespaces=yes", "RestrictRealtime=yes",
	"RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
	"SystemCallArchitectures=native", "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged",
	"UMask=0077", "Restart=always", "RestartSec=2",
}

// PluginUnitName is a side's unit: each side its own, so a control plane that is also a worker can
// run both (they share the program, its credentials and its config).
func PluginUnitName(name, side string) string {
	if side == "node" {
		return "kevaso-plugin-" + name + "-node.service"
	}
	return "kevaso-plugin-" + name + ".service"
}

func (o PluginOptions) side() string {
	if o.Side == "" {
		return "controller"
	}
	return o.Side
}

func pluginEtc(name string) string { return "/etc/kevaso/plugins/" + name }

func parsePlugin(args []string, needBinary bool) (PluginOptions, error) {
	o := PluginOptions{InitOptions: InitOptions{SSHPort: 22}}
	var target string
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch a {
		case "--name":
			o.Name, err = next()
		case "--binary":
			o.Binary, err = next()
		case "--side":
			o.Side, err = next()
		case "--config":
			o.Config, err = next()
		case "--manifest":
			o.Manifest, err = next()
		case "--yes":
			o.Yes = true
		case "--credential":
			return o, errors.New("--credential was removed: pass --cluster-secret NAME (repeatable); kevasod fetches its keys, and the plugin reads each as NAME_KEY from its credential directory")
		case "--cluster-secret":
			var v string
			if v, err = next(); err == nil {
				if !plugins.ValidClusterSecretName(v) {
					return o, fmt.Errorf("--cluster-secret %q: a lower-case name (letters, digits, - and _), not a file and not config", v)
				}
				if !slices.Contains(o.ClusterSecrets, v) {
					o.ClusterSecrets = append(o.ClusterSecrets, v)
				}
			}
		case "--ssh-key":
			o.SSHKey, err = next()
		case "--host-key":
			o.HostKey, err = next()
		case "--ssh-port":
			var v string
			if v, err = next(); err == nil {
				o.SSHPort, err = strconv.Atoi(v)
			}
		case "--accept-host-key-on-first-use":
			o.HostKeyFirstUse = true
		default:
			if strings.HasPrefix(a, "-") || target != "" {
				return o, fmt.Errorf("unexpected %q", a)
			}
			target = a
		}
		if err != nil {
			return o, err
		}
	}
	switch {
	case target == "":
		return o, errors.New("which host? kvoadm plugin install [USER@]ADDRESS --name NAME --binary PATH")
	case !pluginName.MatchString(o.Name):
		return o, errors.New("--name: lower-case letters, digits and -, starting with a letter (e.g. linode)")
	case strings.HasSuffix(o.Name, "-node"):
		return o, fmt.Errorf("--name %s: a name can't end in -node (that is plugin %s's node side)", o.Name, strings.TrimSuffix(o.Name, "-node"))
	case needBinary && o.Binary == "":
		return o, errors.New("--binary: the plugin's program, built for the host (e.g. bin/kevaso-provider-linode-linux-amd64)")
	case o.Side != "" && o.Side != "controller" && o.Side != "node":
		return o, errors.New("--side: controller (on a control plane) or node (on a worker)")
	}
	o.User, o.Address = "root", target
	if u, a, ok := strings.Cut(target, "@"); ok {
		o.User, o.Address = u, a
	}
	return o, nil
}

// pluginCmd: kvoadm plugin install | remove.
func pluginCmd(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	usage := errors.New(`usage:
  kvoadm plugin install [USER@]ADDRESS --name NAME --binary PATH [--cluster-secret NAME]… [--config FILE] [--side controller|node] [--manifest kevaso-plugin.json [--yes]]
  kvoadm plugin remove [USER@]ADDRESS --name NAME [--side controller|node]
  kvoadm plugin install [USER@]ADDRESS --package DIR [--binary PATH] [--api-server URL] [--adopt] [--yes]
  kvoadm plugin uninstall NAME [--force]
  kvoadm plugin list`)
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "install", "uninstall", "list":
		if args[0] != "install" || slices.Contains(args, "--package") {
			return operatorCmd(ctx, args, stdin, out) // operator.go
		}
	}
	switch args[0] {
	case "install":
		o, err := parsePlugin(args[1:], true)
		if err != nil {
			return err
		}
		return pluginInstall(ctx, o, stdin, out)
	case "remove":
		o, err := parsePlugin(args[1:], false)
		if err != nil {
			return err
		}
		return pluginRemove(ctx, o, stdin, out)
	}
	return usage
}

func pluginInstall(ctx context.Context, o PluginOptions, stdin io.Reader, out io.Writer) error {
	say := func(f string, a ...any) { _, _ = fmt.Fprintf(out, "→ "+f+"\n", a...) }
	if err := readManifest(&o); err != nil {
		return err
	}
	in := bufio.NewReader(stdin)
	if err := grantNeeds(o, in, stdin, out); err != nil {
		return err
	}
	unitText, err := PluginUnit(o)
	if err != nil {
		return err
	}
	bin, err := os.ReadFile(o.Binary)
	if err != nil {
		return err
	}
	secretPath, secretRec, secretMode, err := clusterSecretUpload(o)
	if err != nil {
		return err
	}
	var cfg []byte
	if o.Config != "" {
		if cfg, err = os.ReadFile(o.Config); err != nil {
			return err
		}
	}
	kc, err := loadCluster(clusterName(ctx))
	if err != nil {
		return err
	}
	signKey, _, err := SigningKey(kc.Folder()) // the key the cluster's hosts pinned at install
	if err != nil {
		return err
	}
	if len(o.ClusterSecrets) > 0 {
		c, _, err := adminClient(kc.Cluster())
		if err != nil {
			return err
		}
		if err := ensurePluginServiceAccount(ctx, c, o.Name, o.side()); err != nil {
			return err
		}
		say("%s", pluginAccountBindLine(o.Name, o.side()))
	}
	conn, _, err := dialHost(ctx, o.InitOptions, in, stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	name := "kevaso-plugin-" + o.Name
	if err := conn.InstallBinary(ctx, name, bin, ed25519.Sign(signKey, bin)); err != nil {
		return err
	}
	say("%s installed (signature verified on the host)", name)
	if _, err := conn.Run(ctx, "install -d -m 0700 "+sshboot.Quote(pluginEtc(o.Name)), nil); err != nil {
		return err
	}
	if !o.Needs.HostMounts {
		for _, d := range o.Needs.WritePaths { // the unit's namespace needs them there, as real folders
			if _, err := conn.Run(ctx, WritePathScript(d), nil); err != nil {
				return fmt.Errorf("plugin %s: write path %s: %w", o.Name, d, err)
			}
		}
	}
	if secretRec != nil {
		if err := conn.Upload(ctx, secretPath, secretRec, uint32(secretMode)); err != nil {
			return err
		}
		say("cluster secrets %s recorded (kevasod writes each value, root only; the plugin reads it through systemd)", strings.Join(o.ClusterSecrets, ", "))
	}
	if cfg != nil {
		if err := conn.Upload(ctx, pluginEtc(o.Name)+"/config.json", cfg, 0o644); err != nil {
			return err
		}
	}
	if o.ManifestText != nil { // kevasod checks the plugin's device answers against it (K-038)
		if err := conn.Upload(ctx, pluginEtc(o.Name)+"/"+kplugin.ManifestFile, o.ManifestText, 0o600); err != nil {
			return err
		}
	}
	unit := PluginUnitName(o.Name, o.side())
	since, _ := conn.Run(ctx, "date +%s", nil) // kevasod's word on it is looked for from here on
	// A unit whose LoadCredential file is not there yet cannot start. kevasod writes the
	// value and restarts the unit; enable it now and don't wait for it to be active.
	if secretRec != nil {
		if err := conn.Upload(ctx, "/etc/systemd/system/"+unit, []byte(unitText), 0o644); err != nil {
			return err
		}
		if _, err := conn.Run(ctx, "systemctl daemon-reload && systemctl enable "+sshboot.Quote(unit), nil); err != nil {
			return err
		}
		say("plugin %s recorded; kevasod writes its cluster secrets and starts %s", o.Name, unit)
		return nil
	}
	if err := conn.InstallUnit(ctx, unit, []byte(unitText)); err != nil {
		return err
	}
	if _, err := conn.Run(ctx, "sleep 2; systemctl is-active --quiet "+sshboot.Quote(unit), nil); err != nil {
		logs, _ := conn.Run(ctx, "journalctl -u "+sshboot.Quote(unit)+" -n 20 --no-pager", nil)
		return fmt.Errorf("%s didn't stay up:\n%s", unit, logs)
	}
	// kevasod refuses a plugin that claims a class or DNS name another plugin serves, or answers
	// under another name (K-042): that refusal is this install's.
	word, _ := conn.Run(ctx, RegistrationScript(o.Name, strings.TrimSpace(string(since)), 20), nil)
	switch registered, line := Registration(o.Name, string(word)); {
	case line == "":
		say("kevasod on the host hasn't said yet whether it registered plugin %s (journalctl -u kevasod there)", o.Name)
	case !registered:
		_, _ = conn.Run(ctx, "systemctl disable --now "+sshboot.Quote(unit), nil)
		return fmt.Errorf("kevasod refused plugin %s, so its unit %s is stopped: %s", o.Name, unit, line)
	default:
		say("kevasod: %s", line)
	}
	if o.side() == "controller" {
		say("plugin %s running (%s); kevasod registers it from %s/%s/plugin.sock", o.Name, unit, kplugin.Dir, o.Name)
	} else {
		say("plugin %s node side running (%s)", o.Name, unit)
	}
	return nil
}

// RegistrationScript waits up to wait seconds on the host for kevasod's word on plugin name since
// the host's time since (seconds since 1970), and prints that line: registered, answering again,
// or refused (and why).
func RegistrationScript(name, since string, wait int) string {
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(since) {
		since = "0"
	}
	pat := sshboot.Quote(`plugin ` + name + ` ([^ ]+ registered \(|[^ ]+ at [^ ]+ refused: |answering again)`)
	return fmt.Sprintf("i=0; while [ $i -lt %d ]; do l=$(journalctl -u kevasod.service --since @%s -o cat --no-pager 2>/dev/null | grep -E %s | tail -n 1); "+
		"if [ -n \"$l\" ]; then printf '%%s\\n' \"$l\"; exit 0; fi; i=$((i+1)); sleep 1; done; exit 0", wait, since, pat)
}

// Registration reads RegistrationScript's output: whether kevasod registered plugin name, and
// what it said ("": nothing yet).
func Registration(name, out string) (registered bool, line string) {
	l := strings.TrimSpace(out)
	i := strings.Index(l, "plugin "+name+" ")
	if i < 0 {
		return false, ""
	}
	l = l[i:]
	return !strings.Contains(l, " refused: "), l
}

func pluginRemove(ctx context.Context, o PluginOptions, stdin io.Reader, out io.Writer) error {
	conn, _, err := dialHost(ctx, o.InitOptions, bufio.NewReader(stdin), stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Run(ctx, PluginRemoveScript(o.Name, o.side()), nil); err != nil {
		return err
	}
	if c, _, err := adminClient(clusterName(ctx)); err != nil {
		return err
	} else if err := deletePluginServiceAccount(ctx, c, o.Name, o.side()); err != nil {
		return fmt.Errorf("service account %s: %w", operators.ServiceAccountForSide(o.Name, o.side()), err)
	}
	_, _ = fmt.Fprintf(out, "→ plugin %s's %s side removed (its unit and service account %s; the program and credentials once no side is left)\n", o.Name, o.side(), operators.ServiceAccountForSide(o.Name, o.side()))
	return nil
}

// pluginLastSide is what PluginRemoveScript prints when this host has no side of the plugin left.
const pluginLastSide = "kevaso-plugin-last-side"

// lastPluginSide reports that output: the other side's unit was already gone, so the program
// and the service account go with this removal.
func lastPluginSide(output string) bool { return strings.Contains(output, pluginLastSide) }

// pluginAccountBindLine is the one line install prints: which account the admin binds.
// side is "node" or the controller side. A secret both sides need is bound to both accounts.
func pluginAccountBindLine(plugin, side string) string {
	return fmt.Sprintf("bind a ClusterRole to service account %s in namespace %s", operators.ServiceAccountForSide(plugin, side), v1.PluginNamespace)
}

// ensurePluginServiceAccount makes namespace kevaso-system and the service account for side
// (plugin-NAME, or plugin-NAME-node), creating either only when it is missing. It does not
// create a role or a binding, and it does not change an account that is already there.
//
// The namespace needs nothing special. Its name is not a network name (mesh, internal,
// external), and it is not a public suffix, so it does not take over names the way a
// namespace called com would (K-075). Creating a namespace adds no binding: a tenant reaches
// it only when someone binds them there.
func ensurePluginServiceAccount(ctx context.Context, c *client.Client, plugin, side string) error {
	if names.Reserved(v1.PluginNamespace) {
		return fmt.Errorf("namespace %s is a network's name", v1.PluginNamespace)
	}
	ns := &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"},
		ObjectMeta: meta.ObjectMeta{Name: v1.PluginNamespace}}
	if err := c.Create(ctx, ns); err != nil && !client.IsAlreadyExists(err) {
		return fmt.Errorf("namespace %s: %w", v1.PluginNamespace, err)
	}
	sa := &v1.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ServiceAccount"},
		ObjectMeta: meta.ObjectMeta{Name: operators.ServiceAccountForSide(plugin, side), Namespace: v1.PluginNamespace}}
	if err := c.Create(ctx, sa); err != nil && !client.IsAlreadyExists(err) {
		return fmt.Errorf("service account %s: %w", sa.Name, err)
	}
	return nil
}

// deletePluginServiceAccount removes the service account of side. Missing is fine: this side
// may never have asked for a cluster secret. The namespace stays; other plugins and the other
// side's account stay.
func deletePluginServiceAccount(ctx context.Context, c *client.Client, plugin, side string) error {
	err := c.Delete(ctx, "ServiceAccount", v1.PluginNamespace, operators.ServiceAccountForSide(plugin, side))
	if err != nil && !client.IsNotFound(err) {
		return err
	}
	return nil
}

// PluginRemoveScript removes one side's unit, and the program, credentials and config the sides
// share once the other side isn't installed either.
func PluginRemoveScript(name, side string) string {
	other := "node"
	if side == "node" {
		other = "controller"
	}
	unit := sshboot.Quote(PluginUnitName(name, side))
	rec := plugins.ClusterSecretsFile
	if side == "node" {
		rec = plugins.ClusterSecretsNodeFile
	}
	return "systemctl disable --now " + unit + " 2>/dev/null; rm -f /etc/systemd/system/" + unit + " " +
		sshboot.Quote(pluginEtc(name)+"/"+rec) + "; systemctl daemon-reload; " +
		"if [ ! -e /etc/systemd/system/" + sshboot.Quote(PluginUnitName(name, other)) + " ]; then rm -f " +
		sshboot.InstallDir + "/" + sshboot.Quote("kevaso-plugin-"+name) + "; rm -rf " + sshboot.Quote(pluginEtc(name)) +
		"; echo " + sshboot.Quote(pluginLastSide) + "; fi"
}

// clusterSecretUpload is the root-only record of this side's cluster-secret names, beside
// the credential files the unit's LoadCredential lines name. kevasod reads it. The record
// holds names only.
func clusterSecretUpload(o PluginOptions) (path string, data []byte, mode os.FileMode, err error) {
	if len(o.ClusterSecrets) == 0 {
		return "", nil, 0, nil
	}
	names := append([]string(nil), o.ClusterSecrets...)
	sort.Strings(names)
	data, err = plugins.EncodeClusterSecrets(names)
	if err != nil {
		return "", nil, 0, err
	}
	return plugins.ClusterSecretsPath(plugins.DefaultManifests, o.Name, o.side()), data, 0o600, nil
}
