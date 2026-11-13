package kvoadm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
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
	BehindNAT   bool   // nothing unsolicited reaches it (a box at home)
	Install     string // worker (default) | control-plane
	StateOnly   bool   // with control-plane: a light system node (systemnodes.go)
	ClusterDNS  string // the control plane's DNS name, on a new system node
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
			if v, err = val(); err == nil && v != "worker" && v != "control-plane" {
				err = errors.New("--install worker or --install control-plane")
			}
			o.Install = v
		case "--state-only":
			o.StateOnly = true
		case "--cluster-dns":
			o.ClusterDNS, err = val()
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
		case "--behind-nat":
			o.BehindNAT = true
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
	switch {
	case len(o.Runtimes) == 0:
		o.Runtimes = []string{"cloud-hypervisor"}
	case len(o.Runtimes) == 1 && o.Runtimes[0] == "none":
		o.Runtimes = nil // a worker with no runtime yet (e.g. a box without KVM, for now)
	}
	if o.Advertise == "" {
		o.Advertise = o.Address
	}
	if o.StateOnly && o.Install != "control-plane" {
		return o, errors.New("--state-only goes with --install control-plane")
	}
	return o, nil
}

// WorkerUnit is the systemd unit of a worker-only host.
func WorkerUnit(o HostAddOptions, server string) string {
	args := []string{"worker", "--name", o.Name, "--server", server}
	for _, r := range o.Runtimes {
		args = append(args, "--runtime", r)
	}
	if len(o.Runtimes) == 0 {
		args = append(args, "--runtime", "none")
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

// FenceUnit is a worker-only host's fence (kevasod fence-watch), separate from kevasod.service.
func FenceUnit(o HostAddOptions) string { return fence.Unit(o.Runtimes, fence.DefaultAfter) }

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
	if err := lookFirst(ctx, o.InitOptions, stdin, out); err != nil {
		return err
	}
	o.looked = true
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
		Spec: v1.HostSpec{Address: o.Advertise, Region: o.Region, Zone: o.Zone, Network: v1.HostNetwork{BehindNAT: o.BehindNAT},
			Components: v1.HostComponents{Worker: &v1.WorkerSpec{Labels: o.Labels, Runtimes: runtimes}}}}
	if err := c.Create(ctx, h); err != nil && !client.IsAlreadyExists(err) {
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
	// Its fence, a unit of its own: when this host's agent can no longer vouch for its silos (cut
	// off, or not running), it stops those the control plane may start elsewhere.
	if err := conn.InstallUnit(ctx, "kevaso-fence.service", []byte(FenceUnit(o))); err != nil {
		return err
	}
	say("fence started (kevaso-fence.service)")
	// How kvoadm reaches it, kept on its Host (and so in backups): kvoadm init --restore uses it to
	// reconnect the worker to a restored control plane.
	if err := annotateSSH(ctx, c, o.Name, fmt.Sprintf("%s@%s", o.User, net.JoinHostPort(o.Address, strconv.Itoa(o.SSHPort))), conn.Fingerprint); err != nil {
		say("couldn't record how to reach %s (%v): after a restore, reconnect it with kvoadm host reconnect", o.Name, err)
	}

	// 4. It joins and reports.
	if err := waitHostReady(ctx, c, o.Name, 3*time.Minute); err != nil {
		journal, _ := conn.Run(ctx, "journalctl -u kevasod -n 20 --no-pager", nil)
		return fmt.Errorf("%w\nkevasod on the host:\n%s", err, journal)
	}
	say("host %s is Ready (it dials out to the control plane; nothing listens on it). Its runtimes install next: kvo watch hosts", o.Name)
	return nil
}

func annotateSSH(ctx context.Context, c *client.Client, name, target, hostKey string) error {
	for attempt := 0; ; attempt++ {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", name, &h); err != nil {
			return err
		}
		if h.Annotations == nil {
			h.Annotations = map[string]string{}
		}
		h.Annotations[AnnotationSSH], h.Annotations[AnnotationSSHHostKey] = target, hostKey
		err := c.Update(ctx, &h)
		if err == nil || !client.IsConflict(err) || attempt > 5 {
			return err
		}
	}
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
		return errors.New("host needs add, install, uninstall, remove, enable-worker, reconnect, list, drain or uncordon")
	}
	switch args[0] {
	case "add":
		o, err := parseHostAdd(args[1:])
		if err != nil {
			return err
		}
		add := hostAdd
		if o.Install == "control-plane" {
			add = hostAddSystemNode
		}
		if err := add(ctx, o, stdin, out); !errors.Is(err, ErrDryRun) {
			return err
		}
		_, _ = fmt.Fprintln(out, "Dry run: nothing was changed.")
		return nil
	case "enable-worker":
		return enableWorker(ctx, args[1:], stdin, out)
	case "install", "uninstall":
		if len(args) < 3 || args[2] != "control-plane" {
			return fmt.Errorf("host %s HOST control-plane [--state-only] (workers: kvoadm host add / enable-worker)", args[0])
		}
		o, kctx := HostAddOptions{}, ""
		for i := 3; i < len(args); i++ {
			switch {
			case args[i] == "--state-only":
				o.StateOnly = true
			case args[i] == "--ssh-key" && i+1 < len(args):
				o.SSHKey = args[i+1]
				i++
			case args[i] == "--context" && i+1 < len(args):
				kctx = args[i+1]
				i++
			default:
				return fmt.Errorf("unknown flag %s", args[i])
			}
		}
		o.KvoContext = kctx
		if args[0] == "uninstall" {
			return hostRemoveSystemNode(ctx, args[1], kctx, false, out)
		}
		return hostInstallControlPlane(ctx, args[1], o, stdin, out)
	case "remove":
		if len(args) < 2 {
			return errors.New("host remove NAME")
		}
		kctx := ""
		if len(args) == 4 && args[2] == "--context" {
			kctx = args[3]
		}
		return hostRemoveSystemNode(ctx, args[1], kctx, true, out)
	case "reconnect":
		return hostReconnect(ctx, args[1:], stdin, out)
	case "list":
		kctx := ""
		if len(args) == 3 && args[1] == "--context" {
			kctx = args[2]
		}
		return hostList(ctx, kctx, out)
	case "drain", "uncordon":
		if len(args) < 2 {
			return fmt.Errorf("host %s needs NAME", args[0])
		}
		kctx := ""
		if len(args) == 4 && args[2] == "--context" {
			kctx = args[3]
		}
		return hostDrain(ctx, args[1], kctx, args[0] == "uncordon", out)
	}
	return fmt.Errorf("unknown host command %q", args[0])
}

// DrainPlan splits the silos on a host into the ones drain moves off (onHostLoss: Recreate: a
// fresh instance elsewhere) and the ones that stay (Wait: pinned to it by their local disk). Pure.
func DrainPlan(host string, silos []*v1.Silo) (move, stay []*v1.Silo) {
	for _, s := range silos {
		if s.Status.Host != host || s.DeletionTimestamp != nil {
			continue
		}
		if s.Policy() == v1.OnHostLossRecreate {
			move = append(move, s)
		} else {
			stay = append(stay, s)
		}
	}
	return move, stay
}

// hostDrain cordons a host and moves off what can move. uncordon undoes the cordon.
func hostDrain(ctx context.Context, name, kctx string, uncordon bool, out io.Writer) error {
	say := func(f string, a ...any) { _, _ = fmt.Fprintf(out, "→ "+f+"\n", a...) }
	c, _, err := adminClient(kctx)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", name, &h); err != nil {
			return err
		}
		h.Spec.Unschedulable = !uncordon
		err := c.Update(ctx, &h)
		if err == nil {
			break
		}
		if !client.IsConflict(err) || attempt > 5 {
			return err
		}
	}
	if uncordon {
		say("%s is schedulable again", name)
		return nil
	}
	say("%s is cordoned: no new silos land on it", name)
	l, err := c.List(ctx, "Silo", "")
	if err != nil {
		return err
	}
	var silos []*v1.Silo
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return err
		}
		silos = append(silos, obj.(*v1.Silo))
	}
	move, stay := DrainPlan(name, silos)
	now := time.Now().UTC().Truncate(time.Second)
	for _, s := range move {
		s.Status.Host, s.Status.Phase, s.Status.Address, s.Status.Init = "", "Pending", "", nil
		meta.SetCondition(&s.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "Drained",
			Message: "moved off " + name + " by kvoadm host drain: a fresh instance from its image (onHostLoss: Recreate)", ObservedGeneration: s.Generation}, now)
		if err := c.UpdateStatus(ctx, s); err != nil {
			return fmt.Errorf("move %s/%s: %w", s.Namespace, s.Name, err)
		}
		say("%s/%s: recreated elsewhere (onHostLoss: Recreate)", s.Namespace, s.Name)
	}
	for _, s := range stay {
		say("%s/%s stays: onHostLoss %s pins it to %s (its disk is local). Delete it, or change its policy, to empty the host", s.Namespace, s.Name, s.Policy(), name)
	}
	if len(stay) == 0 {
		say("%s is empty of silos once the moved ones are gone", name)
	}
	return nil
}
