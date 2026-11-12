package kvoadm

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"kevaso.com/core/internal/sshboot"
	"kevaso.com/core/sdk/kplugin"
)

// PluginOptions are kvoadm plugin install's flags.
type PluginOptions struct {
	InitOptions
	Name   string
	Binary string
	Side   string            // controller (default: on a control plane, serving the API) | node (on a worker)
	Creds  map[string]string // credential name → local file
	Config string            // a local file: the plugin's settings (not secret)
}

var pluginName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// PluginUnit is the systemd unit a plugin runs as: its own dynamic user, no capabilities, read-only
// system, only the network and its own socket folder; its credentials (a cloud token) through
// systemd's LoadCredential, readable by it alone.
func PluginUnit(o PluginOptions) string {
	bin := "/usr/local/bin/kevaso-plugin-" + o.Name
	exec := bin + " serve --socket " + kplugin.Dir + "/" + o.Name + "/plugin.sock"
	if o.Side == "node" {
		exec = bin + " node"
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
	w("DynamicUser=yes")
	if o.Side != "node" {
		w("RuntimeDirectory=%s/%s", strings.TrimPrefix(kplugin.Dir, "/run/"), o.Name)
		w("RuntimeDirectoryMode=0750")
	}
	names := make([]string, 0, len(o.Creds))
	for n := range o.Creds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w("LoadCredential=%s:%s/%s", n, pluginEtc(o.Name), n)
	}
	if o.Config != "" {
		w("LoadCredential=config:%s/config.json", pluginEtc(o.Name))
	}
	for _, l := range []string{
		"NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=",
		"ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
		"ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes",
		"ProtectClock=yes", "ProtectHostname=yes", "ProtectProc=invisible", "ProcSubset=pid",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", "RestrictNamespaces=yes", "RestrictRealtime=yes",
		"RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
		"SystemCallArchitectures=native", "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged",
		"UMask=0077", "Restart=always", "RestartSec=2",
	} {
		w("%s", l)
	}
	w("")
	w("[Install]")
	w("WantedBy=multi-user.target")
	return b.String()
}

func (o PluginOptions) side() string {
	if o.Side == "" {
		return "controller"
	}
	return o.Side
}

func pluginEtc(name string) string { return "/etc/kevaso/plugins/" + name }

func parsePlugin(args []string, needBinary bool) (PluginOptions, error) {
	o := PluginOptions{InitOptions: InitOptions{SSHPort: 22}, Creds: map[string]string{}}
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
		case "--credential":
			var v string
			if v, err = next(); err == nil {
				n, f, ok := strings.Cut(v, "=")
				if !ok || !regexp.MustCompile(`^[a-z][a-z0-9_-]*$`).MatchString(n) || f == "" {
					return o, fmt.Errorf("--credential %q: want NAME=FILE (the value is read from FILE, never given on the command line)", v)
				}
				o.Creds[n] = f
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
	case needBinary && o.Binary == "":
		return o, errors.New("--binary: the plugin's program, built for the host (e.g. bin/kevaso-provider-linode-linux-amd64)")
	case o.Side != "" && o.Side != "controller" && o.Side != "node":
		return o, errors.New("--side: controller (on a control plane) or node (on a worker)")
	}
	o.User, o.Address = "root", target
	if u, a, ok := strings.Cut(target, "@"); ok {
		o.User, o.Address = u, a
	}
	if o.SSHKey == "" {
		if h, err := os.UserHomeDir(); err == nil {
			if p := filepath.Join(h, ".kevaso", "ssh", "id_ed25519"); fileExists(p) {
				o.SSHKey = p
			}
		}
	}
	return o, nil
}

// pluginCmd: kvoadm plugin install | remove.
func pluginCmd(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	usage := errors.New(`usage:
  kvoadm plugin install [USER@]ADDRESS --name NAME --binary PATH [--credential NAME=FILE]… [--config FILE] [--side controller|node]
  kvoadm plugin remove [USER@]ADDRESS --name NAME [--side controller|node]`)
	if len(args) == 0 {
		return usage
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
	bin, err := os.ReadFile(o.Binary)
	if err != nil {
		return err
	}
	creds := map[string][]byte{}
	for n, f := range o.Creds {
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("--credential %s: %w", n, err)
		}
		creds[n] = []byte(strings.TrimSpace(string(b)))
	}
	var cfg []byte
	if o.Config != "" {
		if cfg, err = os.ReadFile(o.Config); err != nil {
			return err
		}
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	signKey, _, err := SigningKey(filepath.Join(h, ".kevaso"))
	if err != nil {
		return err
	}
	conn, _, err := dialHost(ctx, o.InitOptions, bufio.NewReader(stdin), stdin, out)
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
	names := make([]string, 0, len(creds))
	for n := range creds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := conn.Upload(ctx, pluginEtc(o.Name)+"/"+n, creds[n], 0o600); err != nil {
			return err
		}
		say("credential %s stored on the host (root only; the plugin reads it through systemd)", n)
	}
	if cfg != nil {
		if err := conn.Upload(ctx, pluginEtc(o.Name)+"/config.json", cfg, 0o644); err != nil {
			return err
		}
	}
	unit := name + ".service"
	if err := conn.InstallUnit(ctx, unit, []byte(PluginUnit(o))); err != nil {
		return err
	}
	if _, err := conn.Run(ctx, "sleep 2; systemctl is-active --quiet "+sshboot.Quote(unit), nil); err != nil {
		logs, _ := conn.Run(ctx, "journalctl -u "+sshboot.Quote(unit)+" -n 20 --no-pager", nil)
		return fmt.Errorf("%s didn't stay up:\n%s", unit, logs)
	}
	if o.side() == "controller" {
		say("plugin %s running (%s); kevasod registers it from %s/%s/plugin.sock", o.Name, unit, kplugin.Dir, o.Name)
	} else {
		say("plugin %s node side running (%s)", o.Name, unit)
	}
	return nil
}

func pluginRemove(ctx context.Context, o PluginOptions, stdin io.Reader, out io.Writer) error {
	conn, _, err := dialHost(ctx, o.InitOptions, bufio.NewReader(stdin), stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	name := "kevaso-plugin-" + o.Name
	unit := sshboot.Quote(name + ".service")
	if _, err := conn.Run(ctx, "systemctl disable --now "+unit+" 2>/dev/null; rm -f /etc/systemd/system/"+unit+
		" "+sshboot.InstallDir+"/"+name+"; rm -rf "+sshboot.Quote(pluginEtc(o.Name))+"; systemctl daemon-reload", nil); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "→ plugin %s removed (unit, program, credentials)\n", o.Name)
	return nil
}
