package remote

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/container"
)

// Resetting the machine to clean, in three pure parts and one driver method:
//
//   - Baseline: what the machine looked like fresh (its packages, nftables tables, IP forwarding),
//     recorded once before Kevaso ever ran there, in BaselineDir (not one of Kevaso's paths).
//   - Plan: the steps that take everything Kevaso installed away again, in order (units first,
//     then processes, containers, the network, storage, packages, files, users).
//   - Checklist: the checks that each print what is left (nothing: clean), plus Leftovers, the
//     difference between the baseline and the machine now.
//   - Driver.Reset: read the baseline and the machine, run the plan, run the checklist, and fail
//     with every leftover named.

// Where the test's own state lives on the machine (removed by nothing in the plan).
const (
	BaselineDir  = "/var/lib/kvt-baseline"
	BaselineFile = BaselineDir + "/state"
	// HostsMarker ends every /etc/hosts line a test adds; the reset removes those lines.
	HostsMarker = "# kvt-e2e"
	// StorageImage is the loop file kvoadm's --loop-storage backs the volume group with.
	StorageImage = "/var/lib/kevaso-storage.img"
	// UnitPrefix starts the name of every transient unit a test starts (systemd-run --unit=kvt-…).
	UnitPrefix = "kvt-"
)

// Paths Kevaso (and the tests) write on a host, removed by the reset. Each is under one of
// allowedRoots, which a test checks.
var Paths = []string{
	"/usr/local/bin/kevasod", "/usr/local/bin/kevaso-plugin-*",
	"/etc/kevaso", "/etc/kevaso-silos.nft", "/etc/docker/daemon.json", "/etc/profile.d/kevaso-secrets.sh",
	"/etc/systemd/system/kevasod.service", "/etc/systemd/system/kevaso-*.service", "/etc/systemd/system/kevaso-*.d",
	"/opt/kevaso",
	"/var/lib/kevaso", "/var/lib/kevaso-*", "/var/cache/kevaso",
	"/run/kevaso", "/run/kevaso-*",
	"/var/lib/docker", "/var/lib/containerd", "/etc/docker",
}

// mountPattern matches mount points under Kevaso's paths (an extended regular expression).
const mountPattern = `^/(var/lib/kevaso|run/kevaso|var/lib/docker|var/lib/containerd|opt/kevaso)`

// allowedRoots are the only places the plan removes files under.
var allowedRoots = []string{"/usr/local/bin/kevaso", "/etc/kevaso", "/etc/docker", "/etc/profile.d/kevaso-", "/etc/systemd/system/kevaso",
	"/opt/kevaso", "/var/lib/kevaso", "/var/cache/kevaso", "/run/kevaso", "/var/lib/docker", "/var/lib/containerd"}

// Users Kevaso adds (the runtimes' service users); any other kevaso-* user is removed too.
var Users = []string{cloudhypervisor.VMMUser, cloudhypervisor.VFSUser}

// Processes that must not outlive the reset (pgrep -x names).
var Processes = []string{"kevasod", "cloud-hypervisor", "ch-remote", "virtiofsd", "dockerd", "containerd", "containerd-shim-runc-v2"}

// dockerDeps are what docker.io pulls in on Ubuntu 24.04, removed with it when the baseline
// didn't have them.
var dockerDeps = []string{"containerd", "runc", "bridge-utils", "pigz", "ubuntu-fan", "docker-buildx", "docker-compose-v2"}

// Watched are the packages Kevaso's runtimes install (and their dependencies): the reset purges
// those the baseline didn't have, and the checklist fails if one is still there. Other packages
// that appear (a kernel unattended-upgrades installed) are not Kevaso's and are left alone.
func Watched() []string {
	seen := map[string]bool{}
	var out []string
	add := func(ps ...string) {
		for _, p := range ps {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	add(cloudhypervisor.Packages...)
	for _, ps := range container.Packages {
		add(ps...)
	}
	add(dockerDeps...)
	sort.Strings(out)
	return out
}

// State is what the reset compares with the baseline.
type State struct {
	Packages  []string // installed packages (dpkg status "install ok installed")
	Tables    []string // nftables tables, "FAMILY NAME"
	IPForward string   // net.ipv4.ip_forward
}

// StateScript prints the machine's State in sections (ParseState reads it).
const StateScript = `echo '== packages'
dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1 == "ii" {print $2}' | sort -u
echo '== tables'
nft list tables 2>/dev/null | awk '$1 == "table" {print $2, $3}' | sort -u
echo '== ipforward'
sysctl -n net.ipv4.ip_forward
`

// ParseState reads StateScript's output.
func ParseState(out string) (State, error) {
	var s State
	section := ""
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "== ") {
			section = strings.TrimPrefix(line, "== ")
			seen[section] = true
			continue
		}
		switch section {
		case "packages":
			s.Packages = append(s.Packages, line)
		case "tables":
			s.Tables = append(s.Tables, strings.Join(strings.Fields(line), " "))
		case "ipforward":
			s.IPForward = line
		default:
			return State{}, fmt.Errorf("state: a line outside any section: %q", line)
		}
	}
	for _, want := range []string{"packages", "tables", "ipforward"} {
		if !seen[want] {
			return State{}, fmt.Errorf("state: no %q section", want)
		}
	}
	if len(s.Packages) == 0 {
		return State{}, errors.New("state: no packages (not a Debian or Ubuntu machine?)")
	}
	if s.IPForward != "0" && s.IPForward != "1" {
		return State{}, fmt.Errorf("state: ip_forward %q", s.IPForward)
	}
	return s, nil
}

// Render is State in StateScript's format (what the baseline file holds).
func (s State) Render() string {
	var b strings.Builder
	b.WriteString("== packages\n")
	for _, p := range s.Packages {
		b.WriteString(p + "\n")
	}
	b.WriteString("== tables\n")
	for _, t := range s.Tables {
		b.WriteString(t + "\n")
	}
	b.WriteString("== ipforward\n" + s.IPForward + "\n")
	return b.String()
}

// Purgeable are the watched packages installed now that the baseline didn't have.
func Purgeable(base, now State) []string {
	watched := Watched()
	var out []string
	for _, p := range now.Packages {
		if slices.Contains(watched, p) && !slices.Contains(base.Packages, p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// ExtraTables are the nftables tables now that the baseline didn't have.
func ExtraTables(base, now State) []string {
	var out []string
	for _, t := range now.Tables {
		if !slices.Contains(base.Tables, t) {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// Leftovers compares the machine with its baseline: watched packages added, tables added,
// packages the baseline had that are gone (a purge took too much), IP forwarding changed.
func Leftovers(base, now State) []string {
	var out []string
	for _, p := range Purgeable(base, now) {
		out = append(out, "package still installed: "+p)
	}
	for _, t := range ExtraTables(base, now) {
		out = append(out, "nftables table still there: "+t)
	}
	for _, p := range base.Packages {
		if !slices.Contains(now.Packages, p) {
			out = append(out, "package of the baseline missing: "+p)
		}
	}
	if base.IPForward != now.IPForward {
		out = append(out, fmt.Sprintf("net.ipv4.ip_forward is %s, was %s", now.IPForward, base.IPForward))
	}
	return out
}

// Step is one thing the reset does: a root shell script. Steps don't stop the reset when they
// fail (everything is tried); the checklist decides whether the machine is clean.
type Step struct {
	Name   string
	Script string
}

// PlanInput is what the plan needs to know about the machine.
type PlanInput struct {
	Purge     []string // packages to purge (Purgeable)
	Tables    []string // nftables tables to delete (ExtraTables), "FAMILY NAME"
	IPForward string   // the baseline's value
}

// Plan is the reset, in order. Pure.
func Plan(in PlanInput) []Step {
	var steps []Step
	add := func(name, script string) { steps = append(steps, Step{name, script}) }

	// 1. Nothing restarts anything: kevasod and the fence first, then every silo, gateway and
	// plugin unit, then the tests' own transient units.
	add("stop kevasod and the fence", `systemctl disable --now kevasod.service kevaso-fence.service 2>/dev/null; true`)
	add("stop every kevaso-* and "+UnitPrefix+"* unit", `for u in $(systemctl list-units --all --plain --no-legend 'kevaso*' '`+UnitPrefix+`*' | awk '{print $1}'); do
  systemctl disable --now "$u" 2>/dev/null; systemctl kill -s KILL "$u" 2>/dev/null
done
for f in /etc/systemd/system/kevaso*.service; do [ -e "$f" ] && systemctl disable "$(basename "$f")" 2>/dev/null; done
true`)
	add("kill what is left", `for p in kevasod cloud-hypervisor ch-remote virtiofsd; do pkill -KILL -x "$(printf %.15s "$p")"; done; sleep 1; true`)

	// 2. Containers and images, while Docker still runs.
	add("remove containers, volumes and images", `if command -v docker >/dev/null && systemctl is-active -q docker; then
  ids=$(docker ps -aq); [ -z "$ids" ] || docker rm -f $ids >/dev/null
  vs=$(docker volume ls -q); [ -z "$vs" ] || docker volume rm -f $vs >/dev/null
  docker system prune -af --volumes >/dev/null
fi
true`)
	add("stop docker", `systemctl disable --now docker.socket docker.service containerd.service 2>/dev/null; true`)

	// 3. The network: links, addresses, tables, forwarding.
	add("delete links (kvbr*, kvt*, kevaso*, docker0)", `for l in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
  case "$l" in kvbr*|kvt*|kevaso*|docker0) ip link del "$l";; esac
done
true`)
	add("delete addresses labelled :kv", `ip -4 -o addr show | awk '$NF ~ /:kv$/ {print $2, $4, $NF}' | while read dev addr label; do ip addr del "$addr" dev "$dev" label "$label"; done; true`)
	var del strings.Builder
	for _, t := range in.Tables {
		f := strings.Fields(t)
		if len(f) == 2 && safeWord(f[0]) && safeWord(f[1]) {
			fmt.Fprintf(&del, "nft delete table %s %s\n", f[0], f[1])
		}
	}
	add("delete nftables tables the baseline didn't have", del.String()+"true")
	fwd := in.IPForward
	if fwd != "1" {
		fwd = "0"
	}
	add("restore net.ipv4.ip_forward", "sysctl -qw net.ipv4.ip_forward="+fwd)

	// 4. Storage: the volume group, only when it sits on the test's loop file.
	add("remove volume group "+cloudhypervisor.VG+" (on the loop file only)", `vg=`+cloudhypervisor.VG+`
if vgs "$vg" >/dev/null 2>&1; then
  pvs=$(pvs --noheadings -o pv_name -S vg_name="$vg" | tr -d ' ')
  for p in $pvs; do
    case "$p" in
    /dev/loop*) b=$(losetup -n -O BACK-FILE "$p" | tr -d ' ')
      [ "$b" = `+StorageImage+` ] || { echo "refusing: volume group $vg is on $p ($b), not `+StorageImage+`" >&2; exit 1; } ;;
    *) echo "refusing: volume group $vg is on $p, a real disk: remove it by hand" >&2; exit 1 ;;
    esac
  done
  lvremove -qq -fy "$vg"; vgremove -qq -fy "$vg"
  for p in $pvs; do pvremove -qq -fy "$p"; done
fi
for d in $(losetup -n -O NAME -j `+StorageImage+`); do losetup -d "$d"; done
rm -f `+StorageImage)

	// 5. Packages Kevaso installed (the baseline didn't have them), then what came with them.
	if len(in.Purge) > 0 {
		var ok []string
		for _, p := range in.Purge {
			if safeWord(p) {
				ok = append(ok, p)
			}
		}
		add("purge "+strings.Join(ok, " "), "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "+strings.Join(ok, " ")+
			" && DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y -qq")
	}

	// 6. Files (nothing mounted under them first), the tests' /etc/hosts lines, users.
	add("unmount what is mounted under Kevaso's paths", `awk '{print $2}' /proc/mounts | grep -E '`+mountPattern+`' | sort -r | while read m; do umount -l "$m"; done; true`)
	add("remove Kevaso's files", "rm -rf "+strings.Join(Paths, " ")+"\nsystemctl daemon-reload; systemctl reset-failed; true")
	add("remove the tests' /etc/hosts lines", `sed -i '/`+HostsMarker+`$/d' /etc/hosts`)
	add("remove kevaso-* users", `for u in $(awk -F: '$1 ~ /^kevaso-/ {print $1}' /etc/passwd); do userdel "$u"; done
for g in $(awk -F: '$1 ~ /^kevaso-/ {print $1}' /etc/group); do groupdel "$g"; done
true`)
	return steps
}

// safeWord is a name the plan may put in a command unquoted.
func safeWord(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.+:", r)
		if !ok {
			return false
		}
	}
	return true
}

// Check is one item of the checklist: a script that prints what is left (nothing: clean) and
// exits 0.
type Check struct {
	Name   string
	Script string
}

// Checklist is everything that must be gone after a reset. Ports are the TCP ports the suite
// opens on the machine (anything listening there, except on loopback, is left over).
func Checklist(ports []int) []Check {
	var portList []string
	for _, p := range ports {
		portList = append(portList, fmt.Sprint(p))
	}
	return []Check{
		{"no Kevaso unit is loaded", `systemctl list-units --all --plain --no-legend 'kevaso*' '` + UnitPrefix + `*' | awk '{print $1}'`},
		{"no Kevaso process runs", `for p in ` + strings.Join(Processes, " ") + `; do pgrep -x "$(printf %.15s "$p")" >/dev/null && echo "$p"; done; true`},
		{"no Kevaso file is left", `for f in ` + strings.Join(Paths, " ") + `; do [ -e "$f" ] && echo "$f"; done; true`},
		{"nothing is mounted under Kevaso's paths", `awk '{print $2}' /proc/mounts | grep -E '` + mountPattern + `'; true`},
		{"no Kevaso link is left", `ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(kvbr|kvt|kevaso|docker0)'; true`},
		{"no :kv address is left", `ip -4 -o addr show | awk '$NF ~ /:kv$/ {print $2, $4}'`},
		{"no nftables table named kevaso*", `nft list tables 2>/dev/null | awk '$3 ~ /^kevaso/ {print $2, $3}'`},
		{"no volume group " + cloudhypervisor.VG, `vgs --noheadings -o vg_name ` + cloudhypervisor.VG + ` 2>/dev/null | tr -d ' '`},
		{"no device-mapper device of " + cloudhypervisor.VG, `dmsetup ls 2>/dev/null | awk '$1 ~ /^` + cloudhypervisor.VG + `-/ {print $1}'`},
		{"no loop device on " + StorageImage, `losetup -n -O NAME -j ` + StorageImage + ` 2>/dev/null`},
		{"no docker", `command -v docker containerd dockerd 2>/dev/null; true`},
		{"no kevaso-* user or group", `awk -F: '$1 ~ /^kevaso-/ {print "user " $1}' /etc/passwd; awk -F: '$1 ~ /^kevaso-/ {print "group " $1}' /etc/group`},
		{"no test line in /etc/hosts", `grep -F -e '` + HostsMarker + `' /etc/hosts; true`},
		{"nothing listens on the suite's ports", `ss -Htlnu | awk '{print $5}' | while read a; do p=${a##*:}; h=${a%:*}
  case "$h" in 127.*|\[::1\]) continue;; esac
  for w in ` + strings.Join(portList, " ") + `; do [ "$p" = "$w" ] && echo "$a"; done
done; true`},
	}
}

// Report runs a checklist and the baseline comparison's results into one error naming every
// leftover, or nil when clean. Pure: outputs are each check's output, by name.
func Report(checks []Check, outputs map[string]string, leftovers []string) error {
	var bad []string
	for _, c := range checks {
		if out := strings.TrimSpace(outputs[c.Name]); out != "" {
			bad = append(bad, fmt.Sprintf("%s: %s", c.Name, strings.ReplaceAll(out, "\n", ", ")))
		}
	}
	bad = append(bad, leftovers...)
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("%w:\n  - %s", ErrNotClean, strings.Join(bad, "\n  - "))
}

// ErrNotClean: the reset left something behind.
var ErrNotClean = errors.New("the machine is not clean after the reset")

// ErrNoBaseline: the machine's fresh state was never recorded.
var ErrNoBaseline = errors.New("no baseline recorded on the machine")

// Ports are the TCP ports the metal suite opens on the machine (its checklist's last item):
// the API, DNS, ingress, and each test's own (test/e2e/METAL.md lists who opens which).
var Ports = []int{53, 80, 443, 2380, 6443,
	18080, 18081, 18082, 18090, 18091, 18092, 18093, 18095, 18096, 18100, 18110, 18111, 18120, 18121}

// Baseline reads the recorded fresh state.
func (d *Driver) Baseline(ctx context.Context) (State, error) {
	out, err := d.Run(ctx, "cat "+BaselineFile+" 2>/dev/null || true", nil)
	if err != nil {
		return State{}, err
	}
	if strings.TrimSpace(out) == "" {
		return State{}, fmt.Errorf("%w (%s): record it on the freshly installed machine with RecordBaseline", ErrNoBaseline, BaselineFile)
	}
	return ParseState(out)
}

// State reads the machine's state now.
func (d *Driver) State(ctx context.Context) (State, error) {
	out, err := d.Run(ctx, StateScript, nil)
	if err != nil {
		return State{}, err
	}
	return ParseState(out)
}

// RecordBaseline records the machine's fresh state, once. It refuses a machine that already has
// anything of Kevaso's (the checklist must pass first), so a baseline can't take in leftovers.
// An existing baseline is kept and returned.
func (d *Driver) RecordBaseline(ctx context.Context) (State, error) {
	if b, err := d.Baseline(ctx); err == nil {
		return b, nil
	} else if !errors.Is(err, ErrNoBaseline) {
		return State{}, err
	}
	if err := d.Check(ctx, nil); err != nil {
		return State{}, fmt.Errorf("not recording a baseline on a machine that isn't fresh (reinstall it): %w", err)
	}
	s, err := d.State(ctx)
	if err != nil {
		return State{}, err
	}
	if _, err := d.Run(ctx, "umask 077 && mkdir -p "+BaselineDir+" && cat > "+BaselineFile, []byte(s.Render())); err != nil {
		return State{}, err
	}
	return s, nil
}

// Check runs the checklist (and, with a baseline, the comparison with it).
func (d *Driver) Check(ctx context.Context, base *State) error {
	checks := Checklist(Ports)
	outputs := map[string]string{}
	var errs []error
	for _, c := range checks {
		out, err := d.Run(ctx, c.Script, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("check %q: %w", c.Name, err))
			continue
		}
		outputs[c.Name] = out
	}
	var left []string
	if base != nil {
		now, err := d.State(ctx)
		if err != nil {
			errs = append(errs, err)
		} else {
			left = Leftovers(*base, now)
		}
	}
	if err := Report(checks, outputs, left); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Reset takes everything Kevaso installed off the machine and checks that nothing is left. Every
// step is tried even when one fails; the error names the failed steps and every leftover.
func (d *Driver) Reset(ctx context.Context) error {
	base, err := d.Baseline(ctx)
	if err != nil {
		return err
	}
	now, err := d.State(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, s := range Plan(PlanInput{Purge: Purgeable(base, now), Tables: ExtraTables(base, now), IPForward: base.IPForward}) {
		if out, err := d.Run(ctx, s.Script, nil); err != nil {
			errs = append(errs, fmt.Errorf("reset step %q: %w: %s", s.Name, err, strings.TrimSpace(out)))
		}
	}
	if err := d.Check(ctx, &base); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
