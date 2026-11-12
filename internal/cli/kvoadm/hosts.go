package kvoadm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/kvoconfig"
)

// HostAddOptions are kvoadm host add's flags, on top of init's SSH ones.
type HostAddOptions struct {
	InitOptions
	Labels      map[string]string
	Region      string
	Zone        string
	Runtimes    []string
	Advertise   string // the Host's address, if not the SSH one
	KvoContext  string // the kvo context to act as (a cluster-admin)
	ServerForIt string // the API URL as the new host reaches it (default: the context's)
}

func parseHostAdd(args []string) (HostAddOptions, error) {
	o := HostAddOptions{Labels: map[string]string{}}
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		var v string
		switch a {
		case "--install":
			if v, err = val(); err == nil && v != "worker" {
				err = errors.New("--install worker is what host add does today (control-plane hosts come with HA)")
			}
		case "--label":
			if v, err = val(); err == nil {
				k, lv, ok := strings.Cut(v, "=")
				if !ok {
					err = fmt.Errorf("--label %q: want key=value", v)
				}
				o.Labels[k] = lv
			}
		case "--region":
			o.Region, err = val()
		case "--zone":
			o.Zone, err = val()
		case "--runtime":
			if v, err = val(); err == nil {
				o.Runtimes = append(o.Runtimes, v)
			}
		case "--address":
			o.Advertise, err = val()
		case "--context":
			o.KvoContext, err = val()
		case "--server":
			o.ServerForIt, err = val()
		default:
			rest = append(rest, a)
		}
		if err != nil {
			return o, err
		}
	}
	init, err := parseInit(rest)
	if err != nil {
		return o, err
	}
	o.InitOptions = init
	if len(o.Runtimes) == 0 {
		o.Runtimes = []string{"cloud-hypervisor"}
	}
	if o.Advertise == "" {
		o.Advertise = o.Address
	}
	return o, nil
}

// WorkerUnit is the systemd unit of a worker-only host.
func WorkerUnit(o HostAddOptions, server string) string {
	args := []string{"worker", "--name", o.Name, "--server", server}
	for _, r := range o.Runtimes {
		args = append(args, "--runtime", r)
	}
	if o.LoopStorage != "" {
		args = append(args, "--loop-storage", "/var/lib/kevaso-storage.img", "--loop-size", o.LoopStorage)
	}
	return `[Unit]
Description=Kevaso worker (kevasod)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/kevasod ` + strings.Join(args, " ") + `
Restart=always
RestartSec=2
StateDirectory=kevaso
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`
}

func adminClient(kctx string) (*client.Client, kvoconfig.Context, error) {
	path, err := kvoconfig.Path()
	if err != nil {
		return nil, kvoconfig.Context{}, err
	}
	cfg, err := kvoconfig.Load(path)
	if err != nil {
		return nil, kvoconfig.Context{}, err
	}
	c, name, err := cfg.Client(path, kctx)
	if err != nil {
		return nil, kvoconfig.Context{}, err
	}
	return c, cfg.Contexts[name], nil
}

// hostAdd sets up a fresh machine as a worker of the cluster in the current kvo context: the Host
// object, a one-time join token, the same SSH bootstrap as init, and `kevasod worker`, which joins
// and from then on only dials out.
func hostAdd(ctx context.Context, o HostAddOptions, stdin io.Reader, out io.Writer) error {
	say := func(f string, a ...any) { _, _ = fmt.Fprintf(out, "→ "+f+"\n", a...) }
	c, kc, err := adminClient(o.KvoContext)
	if err != nil {
		return err
	}
	ca, err := os.ReadFile(kc.CA)
	if err != nil {
		return err
	}
	server := o.ServerForIt
	if server == "" {
		server = kc.Server
	}
	home := o.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		home = filepath.Join(h, ".kevaso")
	}

	// 1. The Host, as declared (kvo get hosts shows it NotReady until its kevasod reports).
	runtimes := make([]v1.RuntimeSpec, 0, len(o.Runtimes))
	for _, r := range o.Runtimes {
		runtimes = append(runtimes, v1.RuntimeSpec{Name: r})
	}
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: o.Name},
		Spec: v1.HostSpec{Address: o.Advertise, Region: o.Region, Zone: o.Zone,
			Components: v1.HostComponents{Worker: &v1.WorkerSpec{Labels: o.Labels, Runtimes: runtimes}}}}
	if err := c.Create(ctx, h); err != nil && !client.IsConflict(err) {
		return fmt.Errorf("register host %s: %w", o.Name, err)
	}
	say("host %s registered (worker; region %s)", o.Name, dashOr(o.Region))

	// 2. A one-time join token, only for this host and role.
	var tok client.JoinTokenResponse
	if err := c.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: o.Name, Roles: []string{"worker"}}, &tok); err != nil {
		return err
	}

	// 3. The machine: SSH once, as for init.
	conn, err := bootstrap(ctx, o.InitOptions, home, stdin, out, say)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Run(ctx, "install -d -m 0755 /etc/kevaso", nil); err != nil {
		return err
	}
	if err := conn.Upload(ctx, "/etc/kevaso/ca.crt", ca, 0o644); err != nil {
		return err
	}
	if err := conn.Upload(ctx, "/etc/kevaso/join-token", []byte(tok.Token), 0o600); err != nil {
		return err
	}
	if err := conn.InstallUnit(ctx, "kevasod.service", []byte(WorkerUnit(o, server))); err != nil {
		return err
	}
	say("worker started (kevasod.service), joining %s", server)

	// 4. It joins and reports.
	if err := waitHostReady(ctx, c, o.Name, 3*time.Minute); err != nil {
		journal, _ := conn.Run(ctx, "journalctl -u kevasod -n 20 --no-pager", nil)
		return fmt.Errorf("%w\nkevasod on the host:\n%s", err, journal)
	}
	say("host %s is Ready (it dials out to the control plane; nothing listens on it). Its runtimes install next: kvo watch hosts", o.Name)
	return nil
}

func dashOr(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// hostList prints the cluster's hosts, the way design §3.4 shows them.
func hostList(ctx context.Context, kctx string, out io.Writer) error {
	c, _, err := adminClient(kctx)
	if err != nil {
		return err
	}
	l, err := c.List(ctx, "Host", "")
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tADDRESS\tREGION\tZONE\tCOMPONENTS\tSTATUS")
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return err
		}
		h := obj.(*v1.Host)
		var comps []string
		if h.Spec.Components.ControlPlane != nil {
			comps = append(comps, "control-plane")
		}
		if h.Spec.Components.Worker != nil {
			comps = append(comps, "worker")
		}
		st := "NotReady"
		if c := meta.FindCondition(h.Status.Conditions, "Ready"); c != nil {
			st = map[meta.ConditionStatus]string{meta.ConditionTrue: "Ready", meta.ConditionFalse: "NotReady", meta.ConditionUnknown: "Unknown"}[c.Status]
			if c.Status != meta.ConditionTrue && c.Message != "" {
				st += " (" + c.Message + ")"
			}
		}
		if h.Spec.Unschedulable {
			st += " · cordoned"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", h.Name, h.Spec.Address, dashOr(h.Spec.Region), dashOr(h.Spec.Zone), strings.Join(comps, ", "), st)
	}
	return tw.Flush()
}

// hostCmd dispatches kvoadm host add|list|… .
func hostCmd(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("host needs add, list, drain or uncordon")
	}
	switch args[0] {
	case "add":
		o, err := parseHostAdd(args[1:])
		if err != nil {
			return err
		}
		return hostAdd(ctx, o, stdin, out)
	case "list":
		kctx := ""
		if len(args) == 3 && args[1] == "--context" {
			kctx = args[2]
		}
		return hostList(ctx, kctx, out)
	}
	return fmt.Errorf("unknown host command %q", args[0])
}
