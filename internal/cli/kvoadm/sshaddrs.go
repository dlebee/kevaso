package kvoadm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/admconfig"
	"kevaso.com/core/internal/sshboot"
)

// How kvoadm reaches a host over SSH. Each admin's cluster folder lists, per host, the addresses
// to try in order (a LAN address, a Tailscale name, …): from the LAN the first answers, from
// outside the next. The address kvoadm host add used is recorded first. The Host's
// kevaso.com/ssh annotation (what host add used, kept on the cluster and in backups) comes last.
// Whichever address answers, its SSH host key must be the one pinned for that host.
//
//	kvoadm host ssh NAME                     the addresses, in order
//	kvoadm host ssh NAME add ADDR…           [USER@]ADDRESS[:PORT], appended
//	kvoadm host ssh NAME remove ADDR…

// reachTimeout is how long kvoadm waits for an address to accept a TCP connection before it
// tries the next one.
var reachTimeout = 4 * time.Second

// hostTargets is the order kvoadm tries a host's addresses in: the cluster folder's list, then the
// Host's annotation, each once. Pure.
func hostTargets(cfg *admconfig.Config, h *v1.Host) []admconfig.Target {
	var out []admconfig.Target
	add := func(t admconfig.Target) {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	if cfg != nil {
		for _, a := range cfg.Addresses(h.Name) {
			if t, err := admconfig.ParseAddress(a, "root", 22); err == nil {
				add(t)
			}
		}
	}
	if user, addr, port, ok := sshTarget(h); ok {
		add(admconfig.Target{User: user, Host: addr, Port: port})
	}
	return out
}

// pinnedHostKey is the SSH host key a host must show: the cluster's record, else the folder's.
func pinnedHostKey(cfg *admconfig.Config, h *v1.Host) string {
	if k := h.Annotations[AnnotationSSHHostKey]; k != "" {
		return k
	}
	if cfg != nil {
		return cfg.HostKey(h.Name)
	}
	return ""
}

// dialHostAt connects to a host at the first of its addresses that answers and shows the pinned
// host key. base carries the SSH key, password choice and the rest; its user, address and port
// are each target's. It returns the options it connected with.
func dialHostAt(ctx context.Context, cfg *admconfig.Config, h *v1.Host, base InitOptions, stdin io.Reader, out io.Writer) (*sshboot.Conn, InitOptions, error) {
	base.direct = true // each address is dialled as given
	if cfg != nil && base.keys == "" {
		base.keys = cfg.Folder()
	}
	targets := hostTargets(cfg, h)
	if len(targets) == 0 {
		return nil, base, fmt.Errorf("kvoadm doesn't know how to reach %s over SSH: kvoadm host ssh %s add [USER@]ADDRESS", h.Name, h.Name)
	}
	if base.HostKey == "" {
		base.HostKey = pinnedHostKey(cfg, h)
	}
	if base.SSHKey == "" && cfg != nil && cfg.SSHKey() != "" && !base.Password {
		base.SSHKey = cfg.SSHKey()
	}
	defaultSSHKey(&base)
	in := bufio.NewReader(stdin)
	var tried []string
	if len(targets) == 1 { // nothing to fall back to: no reachability probe first
		t := targets[0]
		o := base
		o.User, o.Address, o.SSHPort = t.User, t.Host, t.Port
		conn, _, err := dialHost(ctx, o, in, stdin, out)
		if err != nil {
			return nil, o, fmt.Errorf("%s at %s: %w", h.Name, t, err)
		}
		return conn, o, nil
	}
	for _, t := range targets {
		addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
		if err := reachable(ctx, addr); err != nil {
			tried = append(tried, t.String()+": "+err.Error())
			continue
		}
		o := base
		o.User, o.Address, o.SSHPort = t.User, t.Host, t.Port
		conn, _, err := dialHost(ctx, o, in, stdin, out)
		if errors.Is(err, sshboot.ErrHostKey) {
			// Something answers there, but it isn't this host (a LAN address now someone else's).
			tried = append(tried, t.String()+": "+err.Error())
			continue
		}
		if err != nil {
			return nil, o, fmt.Errorf("%s at %s: %w", h.Name, t, err)
		}
		if len(tried) > 0 {
			_, _ = fmt.Fprintf(out, "→ %s reached at %s (%s)\n", h.Name, t, strings.Join(tried, "; "))
		}
		return conn, o, nil
	}
	return nil, base, fmt.Errorf("can't reach %s over SSH at any of its addresses:\n  %s\n(add one that works from here: kvoadm host ssh %s add [USER@]ADDRESS)",
		h.Name, strings.Join(tried, "\n  "), h.Name)
}

// reachable reports whether addr accepts a TCP connection within reachTimeout.
func reachable(ctx context.Context, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, reachTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("no answer in %s", reachTimeout)
		}
		var op *net.OpError
		if errors.As(err, &op) && op.Err != nil {
			return op.Err
		}
		return err
	}
	return c.Close()
}

// recordHostAddress notes in the cluster folder how this laptop reached a host.
func recordHostAddress(cfg *admconfig.Config, name, target, hostKey string, say func(string, ...any)) {
	if cfg == nil {
		return
	}
	if err := cfg.Update(func(c *admconfig.Config) error { c.RecordHost(name, target, hostKey); return nil }); err != nil {
		say("couldn't record %s's address in %s (%v): kvoadm host ssh %s add %s", name, cfg.Folder(), err, name, target)
	}
}

// hostSSH: kvoadm host ssh NAME [add ADDR… [--local] | remove ADDR… | list] [--cluster NAME].
// add puts addresses in the team's list (cluster.yaml); --local in this machine's (local.yaml),
// tried first.
func hostSSH(ctx context.Context, args []string, out io.Writer) error {
	args, cluster, err := takeCluster(args)
	if err != nil {
		return err
	}
	local := false
	var rest []string
	for _, a := range args {
		if a == "--local" {
			local = true
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) == 0 || (len(rest) > 1 && rest[1] != "add" && rest[1] != "remove" && rest[1] != "list") {
		return errors.New("host ssh NAME [list | add ADDR… [--local] | remove ADDR…] [--cluster NAME]")
	}
	cfg, err := loadCluster(cluster)
	if err != nil {
		return err
	}
	name := rest[0]
	op := "list"
	if len(rest) > 1 {
		op = rest[1]
	}
	addrs := rest[min(2, len(rest)):]
	if op != "list" && len(addrs) == 0 {
		return fmt.Errorf("host ssh %s %s needs at least one [USER@]ADDRESS[:PORT]", name, op)
	}
	var h v1.Host
	h.Name = name
	if c, err := cfg.Client(); err == nil { // the cluster's own record, when it can be asked
		var got v1.Host
		if err := c.Get(ctx, "Host", "", name, &got); err == nil {
			h = got
		} else if op == "add" && client.IsNotFound(err) {
			return fmt.Errorf("no host %s in cluster %s", name, cfg.Cluster())
		}
	}
	switch op {
	case "add":
		var added []string
		if err := cfg.Update(func(c *admconfig.Config) (err error) {
			added, err = c.AddAddresses(name, local, addrs...)
			return err
		}); err != nil {
			return err
		}
		where := cfg.SharedPath() + ": commit it for the team"
		if local {
			where = cfg.LocalPath() + ": this machine only"
		}
		_, _ = fmt.Fprintf(out, "→ %s: %d address(es) added (%s)\n", name, len(added), where)
	case "remove":
		var removed []string
		if err := cfg.Update(func(c *admconfig.Config) error { removed = c.RemoveAddresses(name, addrs...); return nil }); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "→ %s: %d address(es) removed\n", name, len(removed))
	}
	targets := hostTargets(cfg, &h)
	if len(targets) == 0 {
		_, _ = fmt.Fprintf(out, "%s: no SSH address (kvoadm host ssh %s add [USER@]ADDRESS)\n", name, name)
		return nil
	}
	from := map[admconfig.Target]string{}
	for _, list := range []struct {
		addrs []string
		label string
	}{{cfg.Shared.Hosts[name].Addresses, "team (cluster.yaml)"}, {cfg.Local.Hosts[name].Addresses, "this machine (local.yaml)"}} {
		for _, a := range list.addrs {
			if t, err := admconfig.ParseAddress(a, "root", 22); err == nil {
				from[t] = list.label
			}
		}
	}
	tw := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	for i, t := range targets {
		label := from[t]
		if label == "" {
			label = "the cluster's record (" + AnnotationSSH + ")"
		}
		_, _ = fmt.Fprintf(tw, "%d.\t%s\t%s\n", i+1, t, label)
	}
	return tw.Flush()
}

// clusterCtxKey carries --cluster to the commands that take an address rather than a host.
type clusterCtxKey struct{}

func withCluster(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, clusterCtxKey{}, name)
}

// clusterName is the --cluster a command given an address was run with ("" when none).
func clusterName(ctx context.Context) string {
	name, _ := ctx.Value(clusterCtxKey{}).(string)
	return name
}

// takeCluster removes --cluster NAME from args. It returns the rest and the name.
func takeCluster(args []string) ([]string, string, error) {
	var rest []string
	var name string
	for i := 0; i < len(args); i++ {
		if args[i] == "--cluster" {
			if i+1 >= len(args) {
				return nil, "", errors.New("--cluster needs a value")
			}
			name = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return rest, name, nil
}

// targetCluster is the cluster folder for a command given an address: --cluster, else
// $KVOADM_CLUSTER, else the only one. nil when there is none (a machine before any init).
func targetCluster(ctx context.Context) *admconfig.Config {
	kc, err := loadCluster(clusterName(ctx))
	if err != nil {
		return nil
	}
	return kc
}

// prepareTarget fills in what o leaves out from the cluster folder: the SSH key (the folder's
// sshKey, else kvoadm's own key in it) and the folder for kvoadm's keys.
func prepareTarget(kc *admconfig.Config, o *InitOptions) {
	if kc != nil {
		if o.keys == "" {
			o.keys = kc.Folder()
		}
		if o.SSHKey == "" && kc.SSHKey() != "" && !o.Password {
			o.SSHKey = kc.SSHKey()
		}
	}
	defaultSSHKey(o)
}
