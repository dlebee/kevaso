package kvoadm

import (
	"context"
	"crypto/ed25519"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/admconfig"
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

const devVersion = "v0.0.0-dev"

// binaryVersionOf reads the version stamped into bin. Empty when the build set none.
func binaryVersionOf(bin string) string {
	bi, err := buildinfo.ReadFile(bin)
	if err != nil {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "-ldflags" {
			if v := BinaryVersion(s.Value); v != "" {
				return v
			}
		}
	}
	return ""
}

// UpgradeTarget is the version a roll waits for. stamped is the version in the binary.
// A binary with no version is refused, including when flag names one: the binary reports
// only the version it was built with. A flag that names a different version is refused.
func UpgradeTarget(stamped, flag string) (string, error) {
	if stamped == "" || stamped == devVersion {
		return "", fmt.Errorf("this kevasod carries no version (build it with -X %s=vX.Y.Z): --version is refused", versionVar)
	}
	if flag != "" && flag != stamped {
		return "", fmt.Errorf("--version %s is refused: this kevasod reports %s", flag, stamped)
	}
	return stamped, nil
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
		case "--cluster":
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
	stamped := binaryVersionOf(bin)
	target, err := UpgradeTarget(stamped, target)
	if err != nil {
		return fmt.Errorf("%s: %w", bin, err)
	}
	c, kc, err := adminClient(kctx)
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
	signKey, _, err := SigningKey(kc.Folder()) // the key the cluster's hosts pinned at install
	if err != nil {
		return err
	}
	d := &sshDriver{c: c, kc: kc, bin: data, sig: ed25519.Sign(signKey, data), sshKey: sshKey, stdin: stdin, out: out, started: map[string]time.Time{}}
	return upgrade.Execute(ctx, plan, d, func(s string) { _, _ = fmt.Fprintln(out, "→ "+s) })
}

// sshDriver upgrades real hosts: over SSH as install does, health from the Hosts.
type sshDriver struct {
	c       *client.Client
	kc      *admconfig.Config // this laptop's addresses for each host, and the cluster's keys
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
	conn, _, err := dialHostAt(ctx, d.kc, &h, InitOptions{SSHKey: d.sshKey}, d.stdin, d.out)
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
	_, err = conn.Run(ctx, upgradeRestart, nil)
	return err
}

// upgradeRestart starts the new binary: the fence watcher first, where the host has one (K-067:
// an old watcher reads the new record its own way), then kevasod.
const upgradeRestart = "if systemctl cat " + FenceUnitName + " >/dev/null 2>&1; then systemctl restart " + FenceUnitName + "; fi && systemctl restart kevasod"

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
