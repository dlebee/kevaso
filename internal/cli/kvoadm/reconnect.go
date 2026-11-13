package kvoadm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Annotations kvoadm host add leaves on a worker's Host: how kvoadm reaches the machine over SSH.
// They're in the store, so a backup carries them, and kvoadm init --restore can reconnect each
// worker to the restored control plane without asking.
const (
	AnnotationSSH        = "kevaso.com/ssh"          // USER@ADDRESS:PORT
	AnnotationSSHHostKey = "kevaso.com/ssh-host-key" // SHA256:…
)

// RepointWorkerUnit points a worker's systemd unit at another control plane: --server's value is
// replaced. It reports whether anything changed. Pure.
func RepointWorkerUnit(unit, server string) (string, bool, error) {
	lines := strings.Split(unit, "\n")
	for i, l := range lines {
		rest, ok := strings.CutPrefix(l, "ExecStart=/usr/local/bin/kevasod ")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 || f[0] != "worker" {
			return "", false, errors.New("this machine's kevasod isn't a worker (a control-plane host is restored with kvoadm init --restore)")
		}
		for j := 1; j < len(f); j++ {
			if f[j] == "--server" && j+1 < len(f) {
				if f[j+1] == server {
					return unit, false, nil
				}
				f[j+1] = server
				lines[i] = "ExecStart=/usr/local/bin/kevasod " + strings.Join(f, " ")
				return strings.Join(lines, "\n"), true, nil
			}
		}
		return "", false, errors.New("the worker's unit has no --server")
	}
	return "", false, errors.New("no kevasod ExecStart in the unit: is this a Kevaso worker (kvoadm host add)?")
}

// unitFlag is a flag's value in a kevasod ExecStart line ("" if absent). Pure.
func unitFlag(unit, flag string) string {
	for _, l := range strings.Split(unit, "\n") {
		if rest, ok := strings.CutPrefix(l, "ExecStart=/usr/local/bin/kevasod "); ok {
			f := strings.Fields(rest)
			for j := 0; j+1 < len(f); j++ {
				if f[j] == flag {
					return f[j+1]
				}
			}
		}
	}
	return ""
}

// controlPlaneServer is the API URL hosts should dial: the control-plane Host's address, port 6443.
func controlPlaneServer(ctx context.Context, c *client.Client) (string, error) {
	l, err := c.List(ctx, "Host", "")
	if err != nil {
		return "", err
	}
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return "", err
		}
		if h := obj.(*v1.Host); h.Spec.Components.ControlPlane != nil && h.Reach() != "" {
			return "https://" + net.JoinHostPort(h.Reach(), "6443"), nil
		}
	}
	return "", errors.New("no control-plane host in the cluster: give --server")
}

// reconnect points the worker reached through o at server and waits until it reports there.
func reconnect(ctx context.Context, o InitOptions, server string, c *client.Client, stdin io.Reader, out io.Writer) (string, error) {
	conn, _, err := dialHost(ctx, o, bufio.NewReader(stdin), stdin, out)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	unit, err := conn.Run(ctx, "cat /etc/systemd/system/kevasod.service", nil)
	if err != nil {
		return "", err
	}
	name := unitFlag(string(unit), "--name")
	updated, changed, err := RepointWorkerUnit(string(unit), server)
	if err != nil {
		return name, err
	}
	since := time.Now()
	if changed {
		if err := conn.InstallUnit(ctx, "kevasod.service", []byte(updated)); err != nil {
			return name, err
		}
	}
	if err := waitHeartbeat(ctx, c, name, since, 2*time.Minute); err != nil {
		journal, _ := conn.Run(ctx, "journalctl -u kevasod -n 15 --no-pager", nil)
		return name, fmt.Errorf("%w\nkevasod on the host:\n%s", err, journal)
	}
	return name, nil
}

// waitHeartbeat waits for a host to report after since (a restored store still says Ready from
// before, so the condition alone proves nothing).
func waitHeartbeat(ctx context.Context, c *client.Client, name string, since time.Time, d time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	for {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", name, &h); err == nil && h.Status.LastHeartbeat != nil &&
			h.Status.LastHeartbeat.After(since) && meta.IsTrue(h.Status.Conditions, "Ready") {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("host %s didn't report to the control plane in %v", name, d)
		case <-time.After(time.Second):
		}
	}
}

// hostReconnect: kvoadm host reconnect [USER@]ADDRESS [--server URL] [--context C] + SSH flags.
func hostReconnect(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	var server, kctx string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server", "--context":
			if i+1 >= len(args) {
				return fmt.Errorf("%s needs a value", args[i])
			}
			if args[i] == "--server" {
				server = args[i+1]
			} else {
				kctx = args[i+1]
			}
			i++
		default:
			rest = append(rest, args[i])
		}
	}
	o, err := parseTarget(rest)
	if err != nil {
		return err
	}
	defaultSSHKey(&o)
	c, _, err := adminClient(kctx)
	if err != nil {
		return err
	}
	if server == "" {
		if server, err = controlPlaneServer(ctx, c); err != nil {
			return err
		}
	}
	if o.HostKey == "" { // the key kvoadm host add saw, if it recorded this machine
		o.HostKey = recordedHostKey(ctx, c, o)
	}
	name, err := reconnect(ctx, o, server, c, stdin, out)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "→ host %s reports to %s again\n", name, server)
	return nil
}

func recordedHostKey(ctx context.Context, c *client.Client, o InitOptions) string {
	l, err := c.List(ctx, "Host", "")
	if err != nil {
		return ""
	}
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			continue
		}
		h := obj.(*v1.Host)
		if _, addr, port, ok := sshTarget(h); ok && addr == o.Address && port == o.SSHPort {
			return h.Annotations[AnnotationSSHHostKey]
		}
	}
	return ""
}

func defaultSSHKey(o *InitOptions) {
	if o.SSHKey != "" || o.Password {
		return
	}
	if h, err := os.UserHomeDir(); err == nil {
		if p := filepath.Join(h, ".kevaso", "ssh", "id_ed25519"); fileExists(p) {
			o.SSHKey = p
		}
	}
}

// sshTarget reads a Host's SSH annotation (USER@ADDRESS:PORT). Pure.
func sshTarget(h *v1.Host) (user, addr string, port int, ok bool) {
	v := h.Annotations[AnnotationSSH]
	user, hostport, found := strings.Cut(v, "@")
	if !found {
		return "", "", 0, false
	}
	addr, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", "", 0, false
	}
	port, err = strconv.Atoi(p)
	return user, addr, port, err == nil && user != "" && addr != ""
}

// reconnectWorkers is kvoadm init --restore's last step: every worker in the restored cluster,
// pointed at the new control plane, over SSH with the key you restored with (or kvoadm's own).
// What it can't reach is listed with the command to run.
func reconnectWorkers(ctx context.Context, o InitOptions, c *client.Client, server string, stdin io.Reader, out io.Writer) error {
	l, err := c.List(ctx, "Host", "")
	if err != nil {
		return err
	}
	type miss struct{ name, why, cmd string }
	var missed []miss
	n := 0
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return err
		}
		h := obj.(*v1.Host)
		if h.Spec.Components.Worker == nil || h.Spec.Components.ControlPlane != nil {
			continue
		}
		n++
		user, addr, port, ok := sshTarget(h)
		cmd := fmt.Sprintf("kvoadm host reconnect root@%s --ssh-key KEY --server %s", h.Reach(), server)
		if !ok {
			missed = append(missed, miss{h.Name, "added before kvoadm recorded how to reach it", cmd})
			continue
		}
		cmd = fmt.Sprintf("kvoadm host reconnect %s@%s --ssh-port %d --ssh-key KEY --server %s", user, addr, port, server)
		wo := InitOptions{User: user, Address: addr, SSHPort: port, SSHKey: o.SSHKey, HostKey: h.Annotations[AnnotationSSHHostKey]}
		if wo.HostKey == "" {
			missed = append(missed, miss{h.Name, "no host key recorded", cmd})
			continue
		}
		defaultSSHKey(&wo)
		if _, err := reconnect(ctx, wo, server, c, strings.NewReader(""), io.Discard); err != nil {
			missed = append(missed, miss{h.Name, firstLine(err.Error()), cmd})
			continue
		}
		_, _ = fmt.Fprintf(out, "→ worker %s reconnected (%s)\n", h.Name, server)
	}
	if n == 0 || len(missed) == 0 {
		return nil
	}
	_, _ = fmt.Fprintf(out, "\n%d of %d workers still point at the old control plane:\n\n", len(missed), n)
	tw := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(tw, "HOST\tWHY\tRUN")
	for _, m := range missed {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", m.name, m.why, m.cmd)
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintln(out)
	return nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// sshAddress is the address kvoadm reaches a host at over SSH: the one the operator typed when
// adding it (its kevaso.com/ssh annotation), else where other hosts reach it.
func sshAddress(h *v1.Host) string {
	if _, addr, _, ok := sshTarget(h); ok {
		return addr
	}
	return h.Reach()
}
