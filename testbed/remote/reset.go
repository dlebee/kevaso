package remote

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/hostreset"
)

// The test machine's reset is kvoadm reset's plan and checklist (internal/hostreset), against a
// baseline of the test's own: the machine's fresh state, recorded once in BaselineDir (not one of
// Kevaso's paths, so no reset removes it) before Kevaso ever ran there. The machine has no Docker
// when the baseline is recorded (RecordBaseline refuses it otherwise), so Docker (and podman) is always the
// reset's to remove, and the volume group only ever sits on Kevaso's loop file.

// Where the test's own state lives on the machine.
const (
	BaselineDir  = "/var/lib/kvt-baseline"
	BaselineFile = BaselineDir + "/state"
	HostsMarker  = hostreset.HostsMarker
	StorageImage = hostreset.StorageImage
	UnitPrefix   = hostreset.TestUnitPrefix
)

// Ports are the TCP ports the metal suite opens on the machine (its checklist's last item):
// the API, DNS, ingress, and each test's own (test/e2e/METAL.md lists who opens which).
var Ports = []int{53, 80, 443, 2380, 6443,
	18080, 18081, 18082, 18090, 18091, 18092, 18093, 18095, 18096, 18100, 18110, 18111, 18120, 18121, 18130, 18140, 18141}

// ErrNoBaseline: the machine's fresh state was never recorded.
var ErrNoBaseline = errors.New("no baseline recorded on the machine")

// ErrNotClean: the reset left something behind.
var ErrNotClean = hostreset.ErrNotClean

// State is the machine's state as the reset compares it.
type State = hostreset.State

// CacheDir keeps what every run downloads again (the Ubuntu cloud image, Cloud Hypervisor's
// release): outside Kevaso's paths, so no reset removes it. Kevaso's own caches are saved here
// before a reset (SaveCacheScript) and seeded from it before an install (SeedCacheScript); Kevaso
// still checks every file's digest, so a stale copy is fetched again.
const CacheDir = "/var/cache/kvt"

// SaveCacheScript copies Kevaso's downloads into CacheDir.
var SaveCacheScript = `mkdir -p ` + CacheDir + `/images ` + CacheDir + `/ch
for f in ` + cloudhypervisor.ImagesDir + `/*.img; do [ -f "$f" ] && cp -f "$f" ` + CacheDir + `/images/; done
for f in ` + cloudhypervisor.BinDir + `/*; do [ -f "$f" ] && cp -f "$f" ` + CacheDir + `/ch/; done
true`

// SeedCacheScript puts CacheDir's files where Kevaso's install looks for them first.
var SeedCacheScript = `[ -d ` + CacheDir + ` ] || exit 0
mkdir -p ` + cloudhypervisor.ImagesDir + ` ` + cloudhypervisor.BinDir + `
for f in ` + CacheDir + `/images/*; do [ -f "$f" ] && cp -f "$f" ` + cloudhypervisor.ImagesDir + `/; done
for f in ` + CacheDir + `/ch/*; do [ -f "$f" ] && cp -f "$f" ` + cloudhypervisor.BinDir + `/; done
true`

// TestPaths are what the suite itself writes on the machine (the stand-in internet, the test registry).
var TestPaths = []string{"/var/lib/kvt-inet", "/var/lib/kvt-registry", "/root/.kvt-push"}

// Checklist is the test machine's checklist: everything gone, Docker and the tests' files
// included, and the spare disk (if it has one) empty.
func Checklist(spare string, listenOK ...string) []hostreset.Check {
	base := hostreset.Checklist(hostreset.CheckOptions{Ports: Ports, DockerGone: true, PodmanGone: true})
	for i, c := range base {
		if c.Name != "nothing listens on Kevaso's ports" {
			continue
		}
		// A worktree lab's dnsmasq listens on its gateway. That is the lab's, not Kevaso's.
		script := "{ " + c.Script + "\n} | grep -vE '" + labDNSListen + "'"
		if len(listenOK) > 0 {
			var ex []string
			for _, a := range listenOK {
				ex = append(ex, "-e '"+a+"'")
			}
			script += " | grep -vxF " + strings.Join(ex, " ")
			base[i].Name += " (but the machine's own " + strings.Join(listenOK, ", ") + ")"
		}
		base[i].Script = script + "; true"
	}
	base = append(base,
		hostreset.Check{Name: "no file of the tests is left", Script: `for f in ` + strings.Join(TestPaths, " ") + `; do [ -e "$f" ] && echo "$f"; done; true`})
	if spare != "" {
		base = append(base, hostreset.Check{Name: "the spare disk " + spare + " is empty",
			Script: `lsblk -nr -o NAME,TYPE,MOUNTPOINT ` + spare + ` | tail -n +2; wipefs -n ` + spare + `; true`})
	}
	return base
}

// A worktree lab (testbed/lab) lives on this same machine: libvirt domains, networks and disks
// named kvl-*, state under /root/kvl, and one nftables table, inet kvl. None of that is Kevaso's.
// kvlab is the only thing that removes it. The reset never grew a step that deletes those
// domains, networks, disks or /root/kvl; the table and the kvl* links are the parts the reset
// would otherwise take, because the table isn't in the baseline and a link named kvl* sits next
// to the kv* links Kevaso uses. Both stay.
const LabTable = "inet kvl"

// labLinkSkip is the case arm that keeps a lab bridge. The surrounding arm is hostreset's.
const labLinkSkip = "kvl*) ;; # worktree lab (testbed/lab): only kvlab deletes these\n  "

// withoutLabTable drops the lab table from the tables a reset would delete.
func withoutLabTable(tables []string) []string {
	var out []string
	for _, t := range tables {
		if t != LabTable {
			out = append(out, t)
		}
	}
	return out
}

// withoutLabLeftover drops the lab table from the baseline comparison, so a reset that left it
// (on purpose) is not reported as dirty for that.
func withoutLabLeftover(left []string) []string {
	var out []string
	for _, l := range left {
		if l == "nftables table still there: "+LabTable {
			continue
		}
		out = append(out, l)
	}
	return out
}

// keepLabLinks makes the link step skip kvl* (a lab bridge such as kvlbr1).
func keepLabLinks(steps []hostreset.Step) []hostreset.Step {
	const old = "case \"$l\" in kvbr*|kvt*|kevaso*) ip link del \"$l\";; esac"
	const neu = "case \"$l\" in\n  " + labLinkSkip + "kvbr*|kvt*|kevaso*) ip link del \"$l\";;\nesac"
	for i := range steps {
		steps[i].Script = strings.ReplaceAll(steps[i].Script, old, neu)
	}
	return steps
}

// labDNSListen is dnsmasq on a lab network's gateway (10.77.N.1:53, N in 1..6). The checklist
// keeps Kevaso's port 53 clear and must not treat the lab's own DNS as Kevaso listening.
const labDNSListen = `^10\.77\.[1-6]\.1(%[^:]*)?:53$`

// Plan is the test machine's reset plan, from its baseline and its state now: kvoadm reset's,
// then the tests' own files. With a spare disk, the volume group may be on it (and only on it):
// it's wiped, and the disk left with nothing on it. A worktree lab is left in place (LabTable).
func Plan(base, now State, spare string) []hostreset.Step {
	steps := hostreset.Plan(hostreset.PlanInput{Purge: hostreset.Purgeable(base, now), Tables: withoutLabTable(hostreset.ExtraTables(base, now)),
		IPForward: base.IPForward, DockerOurs: true, PodmanOurs: true, Storage: hostreset.StorageLoop})
	if spare != "" {
		for i, st := range steps {
			if strings.HasPrefix(st.Name, "remove volume group") {
				steps[i] = hostreset.Step{Name: "remove volume group " + hostreset.VG + " (on the loop file or the spare disk " + spare + " only)", Script: spareScript(spare)}
			}
		}
	}
	steps = append(steps, hostreset.Step{Name: "remove the tests' files", Script: "rm -rf " + strings.Join(TestPaths, " ")})
	return keepLabLinks(steps)
}

// spareScript removes the volume group when every physical volume of it is the spare disk or
// Kevaso's loop file, then leaves the spare disk with nothing on it, only when it has no
// partitions and isn't mounted.
func spareScript(spare string) string {
	return `vg=` + hostreset.VG + `; d=` + spare + `
if vgs "$vg" >/dev/null 2>&1; then
  pvs=$(pvs --noheadings -o pv_name -S vg_name="$vg" | tr -d ' ')
  for p in $pvs; do
    case "$p" in
    "$d") ;;
    /dev/loop*) b=$(losetup -n -O BACK-FILE "$p" | tr -d ' ')
      [ "$b" = ` + hostreset.StorageImage + ` ] || { echo "refusing: volume group $vg is on $p ($b)" >&2; exit 1; } ;;
    *) echo "refusing: volume group $vg is on $p, not the spare disk $d" >&2; exit 1 ;;
    esac
  done
  lvremove -qq -fy "$vg"; vgremove -qq -fy "$vg"
  for p in $pvs; do pvremove -qq -fy "$p"; done
fi
for l in $(losetup -n -O NAME -j ` + hostreset.StorageImage + `); do losetup -d "$l"; done
rm -f ` + hostreset.StorageImage + `
[ -b "$d" ] || exit 0
n=$(lsblk -nr -o NAME "$d" | wc -l)
[ "$n" = 1 ] || { echo "refusing: the spare disk $d has partitions or holders" >&2; exit 1; }
lsblk -nr -o MOUNTPOINT "$d" | grep -q . && { echo "refusing: the spare disk $d is mounted" >&2; exit 1; }
wipefs -a -q "$d"`
}

// Baseline reads the recorded fresh state.
func (d *Driver) Baseline(ctx context.Context) (State, error) {
	out, err := d.Run(ctx, "cat "+BaselineFile+" 2>/dev/null || true", nil)
	if err != nil {
		return State{}, err
	}
	if strings.TrimSpace(out) == "" {
		return State{}, fmt.Errorf("%w (%s): record it on the freshly installed machine with RecordBaseline", ErrNoBaseline, BaselineFile)
	}
	return hostreset.ParseState(out)
}

// State reads the machine's state now.
func (d *Driver) State(ctx context.Context) (State, error) {
	out, err := d.Run(ctx, hostreset.StateScript, nil)
	if err != nil {
		return State{}, err
	}
	return hostreset.ParseState(out)
}

// RecordBaseline records the machine's fresh state, once. It refuses a machine that already has
// anything of Kevaso's or Docker (the checklist must pass first), so a baseline can't take in
// leftovers. An existing baseline is kept and returned.
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

// Rebaseline records the machine's state now as its baseline in place of the old one, for a
// machine that has gained something of its own a reset must keep (a lab's packages and tables,
// say). Like RecordBaseline it needs the checklist to pass first: nothing of Kevaso's or Docker
// gets in. The old baseline is kept beside it (state.before-TIME). It returns the packages and
// tables the new baseline adds.
func (d *Driver) Rebaseline(ctx context.Context) (added []string, err error) {
	old, err := d.Baseline(ctx)
	if err != nil {
		return nil, err
	}
	if err := d.Check(ctx, nil); err != nil {
		return nil, fmt.Errorf("not re-baselining a machine that isn't clean (reset it first): %w", err)
	}
	s, err := d.State(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range s.Packages {
		if !slices.Contains(old.Packages, p) {
			added = append(added, "package "+p)
		}
	}
	for _, t := range s.Tables {
		if !slices.Contains(old.Tables, t) {
			added = append(added, "table "+t)
		}
	}
	if _, err := d.Run(ctx, "umask 077 && cp -p "+BaselineFile+" "+BaselineFile+".before-$(date -u +%Y%m%dT%H%M%SZ) && cat > "+BaselineFile+".new && mv "+BaselineFile+".new "+BaselineFile, []byte(s.Render())); err != nil {
		return nil, err
	}
	return added, nil
}

// Check runs the checklist (and, with a baseline, the comparison with it).
func (d *Driver) Check(ctx context.Context, base *State) error {
	checks := Checklist(d.Config.SpareDisk, d.Config.ListenOK...)
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
			left = withoutLabLeftover(hostreset.Leftovers(*base, now))
		}
	}
	if err := hostreset.Report(checks, outputs, left); err != nil {
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
	if out, err := d.Run(ctx, SaveCacheScript, nil); err != nil {
		errs = append(errs, fmt.Errorf("saving the download cache: %w: %s", err, strings.TrimSpace(out)))
	}
	for _, s := range Plan(base, now, d.Config.SpareDisk) {
		if out, err := d.Run(ctx, s.Script, nil); err != nil {
			errs = append(errs, fmt.Errorf("reset step %q: %w: %s", s.Name, err, strings.TrimSpace(out)))
		}
	}
	if err := d.Check(ctx, &base); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
