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
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/operators"
	"kevaso.com/core/internal/sshboot"
)

// Plugin operators (ADR 0006): kvoadm plugin install --package, uninstall and list, as a
// cluster-admin of the current kvo context; the controller goes to a host over SSH.

type operatorOptions struct {
	InitOptions
	target, pkg, binary, apiServer, kctx string
	adopt, yes, force                    bool
	rest                                 []string
}

func parseOperator(args []string) (operatorOptions, error) {
	o := operatorOptions{InitOptions: InitOptions{SSHPort: 22}}
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
		case "--package":
			o.pkg, err = next()
		case "--binary":
			o.binary, err = next()
		case "--api-server":
			o.apiServer, err = next()
		case "--context":
			o.kctx, err = next()
		case "--adopt":
			o.adopt = true
		case "--yes":
			o.yes = true
		case "--force":
			o.force = true
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
			if strings.HasPrefix(a, "-") {
				return o, fmt.Errorf("unexpected %q", a)
			}
			o.rest = append(o.rest, a)
		}
		if err != nil {
			return o, err
		}
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

// withTarget sets the SSH target, [USER@]ADDRESS.
func (o operatorOptions) withTarget(target string) operatorOptions {
	o.target, o.User, o.Address = target, "root", target
	if u, a, ok := strings.Cut(target, "@"); ok {
		o.User, o.Address = u, a
	}
	return o
}

func operatorCmd(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	o, err := parseOperator(args[1:])
	if err != nil {
		return err
	}
	in, err := installer(o, out)
	if err != nil {
		return err
	}
	lines := bufio.NewReader(stdin)
	switch args[0] {
	case "install":
		if len(o.rest) != 1 {
			return errors.New("which host runs the controller? kvoadm plugin install [USER@]ADDRESS --package DIR")
		}
		o = o.withTarget(o.rest[0])
		p, err := operators.Load(o.pkg)
		if err != nil {
			return err
		}
		bin := o.binary
		if bin == "" {
			bin = p.BinaryPath()
		}
		prog, err := os.ReadFile(bin)
		if err != nil {
			return fmt.Errorf("the controller program (build it for the host, or --binary PATH): %w", err)
		}
		in.Confirm = func(summary string) bool {
			_, _ = fmt.Fprint(out, summary)
			if o.yes {
				return true
			}
			_, _ = fmt.Fprint(out, "Install it? Type yes: ")
			line, _ := readLine(lines)
			return strings.TrimSpace(line) == "yes"
		}
		return in.Install(ctx, p, &sshHost{o: o, in: lines, stdin: stdin, out: out}, operators.InstallOptions{Program: prog, Adopt: o.adopt})
	case "uninstall":
		if len(o.rest) != 1 {
			return errors.New("kvoadm plugin uninstall NAME [--force]")
		}
		return in.Uninstall(ctx, o.rest[0], func(addr string) (operators.Host, error) {
			return &sshHost{o: o.withTarget(addr), in: lines, stdin: stdin, out: out}, nil
		}, o.force)
	case "list":
		l, err := in.List(ctx, time.Now())
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "NAME\tVERSION\tKINDS\tCONTROLLER\tHOST")
		for _, x := range l {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", x.Name, x.Version, strings.Join(x.Kinds, ","), controllerState(x, time.Now()), x.Host)
		}
		return tw.Flush()
	}
	return errors.New("kvoadm plugin install|uninstall|list")
}

func controllerState(x operators.Listed, now time.Time) string {
	switch {
	case x.Uninstalling:
		return "uninstalling"
	case x.Running:
		return "running"
	case x.Heartbeat == nil:
		return "not running (never reported)"
	}
	return "not running (last seen " + now.Sub(*x.Heartbeat).Truncate(time.Second).String() + " ago)"
}

// installer connects as the current kvo context (a cluster-admin).
func installer(o operatorOptions, out io.Writer) (*operators.Installer, error) {
	path, err := kvoconfig.Path()
	if err != nil {
		return nil, err
	}
	cfg, err := kvoconfig.Load(path)
	if err != nil {
		return nil, err
	}
	c, name, err := cfg.Client(path, o.kctx)
	if err != nil {
		return nil, err
	}
	_, kc, err := cfg.Resolve(name)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(kc.CA)
	if err != nil {
		return nil, err
	}
	server := kc.Server
	if o.apiServer != "" { // how the host reaches the API, when that isn't how this machine does
		server = o.apiServer
	}
	return &operators.Installer{API: c, Server: server, CA: ca, Out: out}, nil
}

// OperatorUnit is the systemd unit a plugin's controller runs as: its own dynamic user, the
// plugins' sandbox, its credentials through LoadCredential (readable by it alone, never on its
// command line or in its environment), and a state directory of its own for its renewed token.
func OperatorUnit(name string) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("[Unit]")
	w("Description=Kevaso plugin %s (controller)", name)
	w("After=network-online.target")
	w("Wants=network-online.target")
	w("")
	w("[Service]")
	w("ExecStart=%s/kevaso-plugin-%s", sshboot.InstallDir, name)
	w("DynamicUser=yes")
	w("StateDirectory=kevaso-plugin-%s", name)
	w("StateDirectoryMode=0700")
	for _, f := range operatorCredentials {
		w("LoadCredential=%s:%s/%s", f, pluginEtc(name), f)
	}
	for _, l := range pluginHardening {
		w("%s", l)
	}
	w("")
	w("[Install]")
	w("WantedBy=multi-user.target")
	return b.String()
}

var operatorCredentials = []string{"ca.pem", "plugin.json", "server", "token.json"}

// sshHost runs a plugin's controller on a host over SSH, as OperatorUnit.
type sshHost struct {
	o     operatorOptions
	in    *bufio.Reader
	stdin io.Reader
	out   io.Writer
}

func (h *sshHost) Address() string { return h.o.target }

func (h *sshHost) dial(ctx context.Context) (*sshboot.Conn, error) {
	conn, _, err := dialHost(ctx, h.o.InitOptions, h.in, h.stdin, h.out)
	return conn, err
}

func (h *sshHost) Start(ctx context.Context, c operators.Controller) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	signKey, _, err := SigningKey(filepath.Join(home, ".kevaso"))
	if err != nil {
		return err
	}
	conn, err := h.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	name := "kevaso-plugin-" + c.Plugin
	if err := conn.InstallBinary(ctx, name, c.Program, ed25519.Sign(signKey, c.Program)); err != nil {
		return err
	}
	if _, err := conn.Run(ctx, "install -d -m 0700 "+sshboot.Quote(pluginEtc(c.Plugin)), nil); err != nil {
		return err
	}
	files := make([]string, 0, len(c.Credentials))
	for f := range c.Credentials {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		if err := conn.Upload(ctx, pluginEtc(c.Plugin)+"/"+f, c.Credentials[f], 0o600); err != nil {
			return err
		}
	}
	unit := name + ".service"
	if err := conn.InstallUnit(ctx, unit, []byte(OperatorUnit(c.Plugin))); err != nil {
		return err
	}
	if _, err := conn.Run(ctx, "sleep 2; systemctl is-active --quiet "+sshboot.Quote(unit), nil); err != nil {
		logs, _ := conn.Run(ctx, "journalctl -u "+sshboot.Quote(unit)+" -n 20 --no-pager", nil)
		return fmt.Errorf("%s didn't stay up:\n%s", unit, logs)
	}
	return nil
}

func (h *sshHost) Stop(ctx context.Context, plugin string) error {
	conn, err := h.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	name := "kevaso-plugin-" + plugin
	unit := sshboot.Quote(name + ".service")
	_, err = conn.Run(ctx, "systemctl disable --now "+unit+" 2>/dev/null; rm -f /etc/systemd/system/"+unit+" "+
		sshboot.InstallDir+"/"+name+"; rm -rf "+sshboot.Quote(pluginEtc(plugin))+" /var/lib/private/"+name+" /var/lib/"+name+"; systemctl daemon-reload", nil)
	return err
}
