package kvoadm

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/upgrade"
)

// kvoadm upgrade --kevasod PATH [--ssh-key PATH] [--batch N] [--version V] [--dry-run]
//
// Rolls a new kevasod across the cluster (internal/upgrade; ADR 0006): the plan first (shown,
// and refused if it breaks the skew rule or the store's majority), then each host in turn over
// SSH, the way install does it: kvoadm signs the binary, the host verifies the signature against
// the key it pinned (E018) before swapping it in, and kevasod restarts. Silos keep running.

const versionVar = "kevaso.com/core/internal/version.Version"

// BinaryVersion reads the version stamped into a kevasod build's -ldflags (pure).
func BinaryVersion(ldflags string) string {
	for _, f := range strings.Fields(ldflags) {
		f = strings.Trim(f, `'"`)
		if v, ok := strings.CutPrefix(f, versionVar+"="); ok {
			return v
		}
	}
	return ""
}

// UpgradeNodes is the cluster as the planner sees it (pure).
func UpgradeNodes(hosts []v1.Host) []upgrade.Node {
	var out []upgrade.Node
	for _, h := range hosts {
		cp := h.Spec.Components.ControlPlane
		n := upgrade.Node{Name: h.Name, System: cp != nil, StateOnly: cp != nil && cp.StateOnly, Worker: h.Spec.Components.Worker != nil,
			Version: h.Status.Version, Ready: meta.IsTrue(h.Status.Conditions, "Ready")}
		if h.Status.ControlPlane != nil {
			n.Leader = h.Status.ControlPlane.Leader
		}
		out = append(out, n)
	}
	return out
}

func upgradeCmd(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	var bin, sshKey, target, kctx string
	batch, dry := 2, false
	for i := 0; i < len(args); i++ {
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", args[i])
			}
			i++
			return args[i], nil
		}
		var err error
		switch args[i] {
		case "--kevasod":
			bin, err = next()
		case "--ssh-key":
			sshKey, err = next()
		case "--version":
			target, err = next()
		case "--context":
			kctx, err = next()
		case "--batch":
			var v string
			if v, err = next(); err == nil {
				batch, err = strconv.Atoi(v)
			}
		case "--dry-run":
			dry = true
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
		if err != nil {
			return err
		}
	}
	if bin == "" {
		return errors.New("--kevasod PATH: the new kevasod (Linux, the hosts' CPU)")
	}
	if _, err := ElfArch(bin); err != nil {
		return err
	}
	if target == "" {
		if bi, err := buildinfo.ReadFile(bin); err == nil {
			for _, s := range bi.Settings {
				if s.Key == "-ldflags" {
					target = BinaryVersion(s.Value)
				}
			}
		}
	}
	if target == "" {
		return fmt.Errorf("%s carries no version (built without -X %s=…): give --version", bin, versionVar)
	}
	c, _, err := adminClient(kctx)
	if err != nil {
		return err
	}
	hosts, err := listHosts(ctx, c)
	if err != nil {
		return err
	}
	plan, err := upgrade.MakePlan(UpgradeNodes(hosts), target, batch)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "Upgrade to %s:\n", plan.Target)
	for i, s := range plan.Steps {
		_, _ = fmt.Fprintf(out, "  %d. %-6s %s\n", i+1, s.Phase, strings.Join(s.Hosts, ", "))
	}
	if len(plan.Current) > 0 {
		_, _ = fmt.Fprintf(out, "  already at %s: %s\n", plan.Target, strings.Join(plan.Current, ", "))
	}
	for _, n := range plan.Notes {
		_, _ = fmt.Fprintf(out, "  note: %s\n", n)
	}
	if dry || len(plan.Steps) == 0 {
		return nil
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	signKey, _, err := SigningKey(filepath.Join(home, ".kevaso"))
	if err != nil {
		return err
	}
	d := &sshDriver{c: c, bin: data, sig: ed25519.Sign(signKey, data), sshKey: sshKey, stdin: stdin, out: out, started: map[string]time.Time{}}
	return upgrade.Execute(ctx, plan, d, func(s string) { _, _ = fmt.Fprintln(out, "→ "+s) })
}

// sshDriver upgrades real hosts: over SSH as install does, health from the Hosts.
type sshDriver struct {
	c       *client.Client
	bin     []byte
	sig     []byte
	sshKey  string
	stdin   io.Reader
	out     io.Writer
	mu      sync.Mutex
	started map[string]time.Time
}

func (d *sshDriver) Majority(ctx context.Context) error {
	hosts, err := listHosts(ctx, d.c)
	if err != nil {
		return err
	}
	ms := membersFromHosts(hosts, time.Now(), 40*time.Second)
	voters, healthy := 0, 0
	for _, m := range ms {
		if !m.Learner {
			voters++
			if m.Healthy {
				healthy++
			}
		}
	}
	if voters <= 1 || healthy-1 > voters/2 {
		return nil
	}
	return fmt.Errorf("%d of %d store members are healthy: no room to restart one", healthy, voters)
}

func (d *sshDriver) Install(ctx context.Context, name string) error {
	var h v1.Host
	if err := d.c.Get(ctx, "Host", "", name, &h); err != nil {
		return err
	}
	user, addr, port, ok := sshTarget(&h)
	if !ok {
		return fmt.Errorf("kvoadm doesn't know how to reach %s over SSH (no %s annotation)", name, AnnotationSSH)
	}
	o := InitOptions{User: user, Address: addr, SSHPort: port, SSHKey: d.sshKey, HostKey: h.Annotations[AnnotationSSHHostKey]}
	defaultSSHKey(&o)
	conn, _, err := dialHost(ctx, o, bufio.NewReader(d.stdin), d.stdin, d.out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.InstallBinary(ctx, "kevasod", d.bin, d.sig); err != nil { // verified on the host first
		return err
	}
	d.mu.Lock()
	d.started[name] = time.Now()
	d.mu.Unlock()
	_, err = conn.Run(ctx, "systemctl restart kevasod", nil)
	return err
}

func (d *sshDriver) Healthy(ctx context.Context, name string, to upgrade.Version) error {
	d.mu.Lock()
	since := d.started[name]
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		var h v1.Host
		if err := d.c.Get(ctx, "Host", "", name, &h); err == nil && h.Status.Version == to.String() &&
			meta.IsTrue(h.Status.Conditions, "Ready") && h.Status.LastHeartbeat != nil && h.Status.LastHeartbeat.After(since.Add(-time.Second)) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s not Ready at %s after 5 minutes", name, to)
		case <-time.After(2 * time.Second):
		}
	}
}
