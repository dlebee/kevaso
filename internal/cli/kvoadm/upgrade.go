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
	"kevaso.com/core/internal/sshboot"
	"kevaso.com/core/internal/upgrade"
)

// kvoadm upgrade --kevasod PATH [--kevasod PATH…] [--ssh-key PATH] [--batch N] [--version V] [--dry-run]
//
// One --kevasod per OS and CPU the cluster has (a Linux build for the Linux hosts, a macOS one for
// the Macs): each host gets the build for its own, and the roll is refused before any host is
// touched when one has none.
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

// PlatformKey names an OS and CPU as uname -s and uname -m say them: "linux/x86_64",
// "darwin/arm64". BinaryTarget gives the same names for a binary.
func PlatformKey(goos, arch string) string { return goos + "/" + arch }

// UnamePlatform reads `uname -sm` ("Linux x86_64", "Darwin arm64") as a PlatformKey.
func UnamePlatform(out string) (string, error) {
	f := strings.Fields(out)
	if len(f) != 2 {
		return "", fmt.Errorf("uname -sm said %q", strings.TrimSpace(out))
	}
	return PlatformKey(strings.ToLower(f[0]), f[1]), nil
}

// MissingBuilds lists the hosts no given kevasod fits, with what each needs (pure). hosts maps a
// host's name to its PlatformKey; have holds the PlatformKeys of the builds given.
func MissingBuilds(hosts map[string]string, have map[string]string) []string {
	var out []string
	for _, name := range sortedKeys(hosts) {
		if _, ok := have[hosts[name]]; !ok {
			out = append(out, name+" ("+hosts[name]+")")
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return ks
}

// upgradeBuilds checks each --kevasod: what it's built for (one per OS and CPU) and that every
// one carries the same version. It returns the PlatformKey → path map and that version.
func upgradeBuilds(bins []string, flag string) (map[string]string, string, error) {
	if len(bins) == 0 {
		return nil, "", errors.New("--kevasod PATH: the new kevasod, one per OS and CPU in the cluster (e.g. Linux x86_64, macOS arm64)")
	}
	builds := map[string]string{}
	target := ""
	for _, bin := range bins {
		goos, arch, err := BinaryTarget(bin)
		if err != nil {
			return nil, "", err
		}
		k := PlatformKey(goos, arch)
		if prev, ok := builds[k]; ok {
			return nil, "", fmt.Errorf("%s and %s are both for %s: give one per OS and CPU", prev, bin, k)
		}
		builds[k] = bin
		v, err := UpgradeTarget(binaryVersionOf(bin), flag)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", bin, err)
		}
		if target != "" && v != target {
			return nil, "", fmt.Errorf("the builds carry different versions (%s and %s): give the same release for every OS", target, v)
		}
		target = v
	}
	return builds, target, nil
}

func upgradeCmd(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	var bins []string
	var sshKey, target, kctx string
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
			var b string
			if b, err = next(); err == nil {
				bins = append(bins, b)
			}
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
	builds, target, err := upgradeBuilds(bins, target)
	if err != nil {
		return err
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
	if len(plan.Steps) == 0 {
		return nil
	}
	d := &sshDriver{c: c, kc: kc, sshKey: sshKey, stdin: stdin, out: out, target: target, started: map[string]time.Time{}, builds: map[string]signedBuild{}}
	// Every host to roll, and what it runs, before any is touched: a host with no build for its
	// OS and CPU refuses the whole roll (a Linux kevasod on a Mac would never start).
	platforms := map[string]string{}
	for _, st := range plan.Steps {
		for _, name := range st.Hosts {
			k, err := d.platform(ctx, name)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			platforms[name] = k
		}
	}
	if missing := MissingBuilds(platforms, builds); len(missing) > 0 {
		return fmt.Errorf("no --kevasod for %s: give a build for each (nothing was changed)", strings.Join(missing, ", "))
	}
	for _, name := range sortedKeys(platforms) {
		_, _ = fmt.Fprintf(out, "  %s: %s, %s\n", name, platforms[name], builds[platforms[name]])
	}
	if dry {
		return nil
	}
	signKey, _, err := SigningKey(kc.Folder()) // the key the cluster's hosts pinned at install
	if err != nil {
		return err
	}
	for k, path := range builds {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		d.builds[k] = signedBuild{data: data, sig: ed25519.Sign(signKey, data)}
	}
	return upgrade.Execute(ctx, plan, d, func(s string) { _, _ = fmt.Fprintln(out, "→ "+s) })
}

// signedBuild is one kevasod build and kvoadm's signature over it.
type signedBuild struct{ data, sig []byte }

// sshDriver upgrades real hosts: over SSH as install does, health from the Hosts.
type sshDriver struct {
	c       *client.Client
	kc      *admconfig.Config      // this laptop's addresses for each host, and the cluster's keys
	builds  map[string]signedBuild // by PlatformKey
	target  string                 // the version each build must report on its host
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

func (d *sshDriver) dial(ctx context.Context, name string) (*sshboot.Conn, error) {
	var h v1.Host
	if err := d.c.Get(ctx, "Host", "", name, &h); err != nil {
		return nil, err
	}
	conn, _, err := dialHostAt(ctx, d.kc, &h, InitOptions{SSHKey: d.sshKey}, d.stdin, d.out)
	return conn, err
}

// platform is the host's OS and CPU as a PlatformKey, read over SSH.
func (d *sshDriver) platform(ctx context.Context, name string) (string, error) {
	conn, err := d.dial(ctx, name)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	o, err := conn.Run(ctx, "uname -sm", nil)
	if err != nil {
		return "", err
	}
	return UnamePlatform(string(o))
}

func (d *sshDriver) Install(ctx context.Context, name string) error {
	conn, err := d.dial(ctx, name)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	o, err := conn.Run(ctx, "uname -sm", nil)
	if err != nil {
		return err
	}
	k, err := UnamePlatform(string(o))
	if err != nil {
		return err
	}
	b, ok := d.builds[k]
	if !ok {
		return fmt.Errorf("no --kevasod for %s (%s)", name, k)
	}
	// Verified on the host first, then run there (kevasod version) before it replaces anything.
	ran, err := conn.InstallBinaryChecked(ctx, "kevasod", b.data, b.sig, "version")
	if err != nil {
		return err
	}
	if got := strings.TrimSpace(ran); got != d.target {
		return fmt.Errorf("the new kevasod on %s reports %q, not %s", name, got, d.target)
	}
	d.mu.Lock()
	d.started[name] = time.Now()
	d.mu.Unlock()
	restart := upgradeRestart
	if goos, _ := conn.OS(ctx); goos == "darwin" {
		restart = MacUpgradeRestart
	}
	_, err = conn.Run(ctx, restart, nil)
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
