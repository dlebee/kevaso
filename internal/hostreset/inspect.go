package hostreset

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/openshell"
)

// InspectScript prints what a reset needs to know about the host, in sections.
var InspectScript = `echo '== record'
cat ` + RecordFile + ` 2>/dev/null | sed 's/^== /=== /'
echo '== kevaso-installed'
cat ` + KevasoInstalledFile + ` 2>/dev/null | sort -u
echo '== installed'
{ [ -e /usr/local/bin/kevasod ] || [ -e /etc/systemd/system/kevasod.service ]; } && echo kevasod=yes || echo kevasod=no
systemctl is-active -q kevasod 2>/dev/null && echo running=yes || echo running=no
echo '== silos'
# microVMs by what is on disk (their units aren't loaded after a reboot): unit files and state.
{ for f in /etc/systemd/system/kevaso-silo-*.service; do [ -e "$f" ] && basename "$f"; done
  systemctl list-units --all --plain --no-legend 'kevaso-silo-*.service' 2>/dev/null | awk '{print $1}'
  for d in ` + cloudhypervisor.SilosDir + `/*/; do [ -d "$d" ] && echo "kevaso-silo-$(basename "$d").service"; done
} | grep -v -- '-fs-' | sort -u | sed 's/^/vm /'
if command -v docker >/dev/null && systemctl is-active -q docker; then
  docker ps -a --filter label=kevaso.com/name --format 'container {{.Label "kevaso.com/namespace"}}/{{.Label "kevaso.com/name"}}' | sort -u
else
` + containerStateLines + `
fi
` + openShellSiloLines(openshell.StateDir) + `
if command -v podman >/dev/null; then
  podman ps -a --filter label=kevaso.com/name --format 'container {{index .Labels "kevaso.com/namespace"}}/{{index .Labels "kevaso.com/name"}} (podman)' | sort -u
fi
echo '== storagefile'
if [ -f ` + StorageImage + ` ]; then
  echo "` + StorageImage + ` $(du -h --apparent-size ` + StorageImage + ` | cut -f1)"
  # Not attached (a reboot): attach it read-only so its volume group and volumes can be seen.
  if [ -z "$(losetup -n -O NAME -j ` + StorageImage + `)" ]; then
    losetup -r -f ` + StorageImage + ` && attached=$(losetup -n -O NAME -j ` + StorageImage + ` | head -1)
    pvscan --cache >/dev/null 2>&1; vgscan >/dev/null 2>&1
  fi
fi
echo '== pvs'
pvs --noheadings -o pv_name -S vg_name=` + VG + ` 2>/dev/null | tr -d ' ' | while read p; do
  case "$p" in /dev/loop*) echo "$p $(losetup -n -O BACK-FILE "$p" | tr -d ' ')";; *) echo "$p disk";; esac
done
echo '== lvs'
lvs --noheadings -o lv_name,lv_size --units g ` + VG + ` 2>/dev/null | awk '$1 != "silos" {print $1, $2}'
echo '== engvols'
if command -v docker >/dev/null && systemctl is-active -q docker; then
  docker volume ls -q --filter label=kevaso.com/uid || echo unreadable
fi
if command -v podman >/dev/null; then
  podman volume ls -q --filter label=kevaso.com/uid || echo unreadable
fi
# What the inspection attached, it detaches (K-078): a kevasod started next must find its pool on
# a writable device.
if [ -n "$attached" ]; then vgchange -an ` + VG + ` >/dev/null 2>&1; losetup -d "$attached"; fi
echo '== state'
` + strings.ReplaceAll(StateScript, "echo '== ", "echo '=== ")

// openShellSiloLines lists OpenShell silos from the runtime's state in dir (their gateways may be
// down, so OpenShell itself can't be asked).
func openShellSiloLines(dir string) string {
	return `for f in ` + dir + `/silos/*.json; do
  [ -f "$f" ] || continue
  ns=$(sed -n 's/.*"Namespace": *"\([^"]*\)".*/\1/p' "$f" | head -1); n=$(sed -n 's/.*"Name": *"\([^"]*\)".*/\1/p' "$f" | head -1)
  echo "openshell $ns/$n"
done`
}

// containerStateLines lists container silos from the container runtime's state on disk, for
// when their engine isn't running (K-078): its containers can't be listed, and would go with
// its directories.
const containerStateLines = `for f in ` + cloudhypervisor.ContainersDir + `/*/state.json; do
  [ -f "$f" ] || continue
  ns=$(sed -n 's/.*"namespace": *"\([^"]*\)".*/\1/p' "$f" | head -1); n=$(sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' "$f" | head -1)
  echo "container $ns/$n (from its state; its engine isn't running)"
done`

// Inspection is the host as a reset sees it.
type Inspection struct {
	Record *Record // nil: no install record (an older install, or never installed)
	// KevasoInstalled are the packages Kevaso's runtimes installed here (KevasoInstalledFile):
	// only those are purged (K-113).
	KevasoInstalled []string
	Installed       bool     // kevasod's binary or unit is there
	Running         bool     // kevasod is active
	Silos           []string // "vm UNIT", "container NS/NAME" or "openshell NS/NAME"
	PVs             []PV     // the volume group's physical volumes (none: no volume group)
	Volumes         []string // its logical volumes but the thin pool, "NAME SIZE"
	// EngineVolumes are docker and podman volumes labelled kevaso.com/uid. EngineVolumesUnknown
	// means a list failed: they may be there.
	EngineVolumes        []string
	EngineVolumesUnknown bool
	// StorageFile is Kevaso's loop file when it exists ("PATH SIZE"), attached or not.
	StorageFile string
	Now         State
}

// PV is one physical volume of the volume group.
type PV struct {
	Device  string
	Backing string // the loop device's file, or "disk"
}

// OnLoopFile says whether the volume group sits on Kevaso's loop file alone.
func (in Inspection) OnLoopFile() bool {
	if len(in.PVs) == 0 {
		return false
	}
	for _, p := range in.PVs {
		if !strings.HasPrefix(p.Device, "/dev/loop") || p.Backing != StorageImage {
			return false
		}
	}
	return true
}

// ParseInspection reads InspectScript's output.
func ParseInspection(out string) (Inspection, error) {
	// Nested sections (the record's and the state's) are written "=== NAME" inside.
	var top, recordText, stateText strings.Builder
	section := ""
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "=== "):
			nested := "== " + strings.TrimPrefix(t, "=== ")
			switch section {
			case "record":
				recordText.WriteString(nested + "\n")
			case "state":
				stateText.WriteString(nested + "\n")
			}
			continue
		case strings.HasPrefix(t, "== "):
			section = strings.TrimPrefix(t, "== ")
		case section == "record":
			recordText.WriteString(t + "\n")
			continue
		case section == "state":
			stateText.WriteString(t + "\n")
			continue
		}
		top.WriteString(t + "\n")
	}
	sec, err := sections(top.String())
	if err != nil {
		return Inspection{}, fmt.Errorf("inspection: %w", err)
	}
	for _, want := range []string{"record", "installed", "silos", "storagefile", "pvs", "lvs", "engvols", "state"} {
		if _, ok := sec[want]; !ok {
			return Inspection{}, fmt.Errorf("inspection: no %q section", want)
		}
	}
	var in Inspection
	in.Installed = slices.Contains(sec["installed"], "kevasod=yes")
	in.Running = slices.Contains(sec["installed"], "running=yes")
	in.Silos = sec["silos"]
	in.KevasoInstalled = sec["kevaso-installed"]
	for _, l := range sec["pvs"] {
		f := strings.Fields(l)
		if len(f) != 2 {
			return Inspection{}, fmt.Errorf("inspection: physical volume line %q", l)
		}
		in.PVs = append(in.PVs, PV{Device: f[0], Backing: f[1]})
	}
	in.Volumes = sec["lvs"]
	for _, l := range sec["engvols"] {
		if l == "unreadable" {
			in.EngineVolumesUnknown = true
			continue
		}
		in.EngineVolumes = append(in.EngineVolumes, l)
	}
	if f := sec["storagefile"]; len(f) > 0 {
		in.StorageFile = f[0]
	}
	if in.Now, err = ParseState(stateText.String()); err != nil {
		return Inspection{}, err
	}
	if strings.TrimSpace(recordText.String()) != "" {
		r, err := ParseRecord(recordText.String())
		if err != nil {
			return Inspection{}, err
		}
		in.Record = &r
	}
	return in, nil
}

// Flags are the operator's choices.
type Flags struct {
	Force       bool // go ahead although silos are on the host
	WipeStorage bool // remove the volume group and its volumes even where they aren't Kevaso's loop file
}

// Decision is what a reset will do.
type Decision struct {
	Plan    PlanInput
	Checks  CheckOptions
	Summary []string // what will be removed and kept, for the operator, before they confirm
	Lost    []string // the volumes (silo data) that will be lost
	// NotOurs are watched packages there now that the record didn't have but Kevaso didn't
	// install either (a person's, after Kevaso): left installed, and not reported as left over.
	NotOurs []string
}

// ErrStrayVolumes: volumes are on Kevaso's storage with no silo on the host, and --wipe-storage
// wasn't given.
var ErrStrayVolumes = errors.New("the host holds volumes no silo here uses")

// ErrSilos: silos are on the host and --force wasn't given.
var ErrSilos = errors.New("the host still runs silos")

// Decide turns an inspection and the flags into the plan, or refuses. Pure.
func Decide(in Inspection, f Flags) (Decision, error) {
	if len(in.Silos) > 0 && !f.Force {
		return Decision{}, fmt.Errorf("%w: %s. Move or delete them first (kvo get silos -A), take the host out of its cluster (kvoadm host drain, then host remove), or reset anyway with --force (their data is lost)",
			ErrSilos, strings.Join(in.Silos, ", "))
	}
	var d Decision
	say := func(f string, a ...any) { d.Summary = append(d.Summary, fmt.Sprintf(f, a...)) }
	d.Checks = CheckOptions{Ports: KevasoPorts}

	say("stop and remove kevasod, the fence and every kevaso-* unit; Kevaso's files (%s)", strings.Join(Paths, " "))
	say("delete Kevaso's links (kvbr*, kvt*, kevaso*) and :kv addresses, and the kevaso-* users")
	if len(in.Silos) > 0 {
		say("destroy the silos still here (--force): %s", strings.Join(in.Silos, ", "))
	}

	if r := in.Record; r != nil {
		// Only what Kevaso's runtimes recorded installing is purged (K-113): a package that came
		// after the record may be the owner's (docker.io installed later: purging it took every
		// container, volume and image on the host).
		for _, p := range Purgeable(r.State, in.Now) {
			if slices.Contains(in.KevasoInstalled, p) {
				d.Plan.Purge = append(d.Plan.Purge, p)
			} else {
				d.NotOurs = append(d.NotOurs, p)
			}
		}
		d.Plan.Tables = ExtraTables(r.State, in.Now)
		d.Plan.IPForward = r.IPForward
		d.Plan.DockerOurs = slices.Contains(d.Plan.Purge, "docker.io")
		if d.Plan.DockerJSON = DockerJSONRemove; r.DockerJSONBefore {
			d.Plan.DockerJSON = DockerJSONRestore
		}
		say("from the install record: purge %s; delete nftables tables %s; set net.ipv4.ip_forward back to %s",
			orNone(d.Plan.Purge), orNone(d.Plan.Tables), r.IPForward)
		if len(d.NotOurs) > 0 {
			say("left installed (not in the install record, but not installed by Kevaso either: someone installed them since): %s", strings.Join(d.NotOurs, " "))
		}
	} else {
		d.Plan.Tables = KevasoTables(in.Now)
		say("NO INSTALL RECORD (an install older than the record): fixed lists only. Delete nftables tables %s; no package is purged; IP forwarding is left as it is",
			orNone(d.Plan.Tables))
		if present := intersect(Watched(), in.Now.Packages); len(present) > 0 {
			say("left installed (Kevaso's runtimes may have installed them, but nothing says so): %s", strings.Join(present, " "))
		}
	}
	if d.Plan.PodmanOurs = slices.Contains(d.Plan.Purge, "podman"); d.Plan.PodmanOurs {
		say("podman was installed by Kevaso: every container, image and its storage (/var/lib/containers) go, then podman itself")
		d.Checks.PodmanGone = true
	}
	switch {
	case d.Plan.DockerOurs:
		say("Docker was installed by Kevaso: every container, volume and image goes, then Docker itself")
		d.Checks.DockerGone = true
	case slices.Contains(d.NotOurs, "docker.io"):
		say("Docker stays (installed after Kevaso, and not by it): Kevaso's containers and volumes go, and the daemon.json Kevaso made")
	case d.Plan.DockerJSON == DockerJSONRestore:
		say("Docker stays (it was there before): Kevaso's containers and volumes go; its daemon.json is put back as it was")
	case d.Plan.DockerJSON == DockerJSONRemove:
		say("Docker stays (it was there before): Kevaso's containers and volumes go, and the daemon.json Kevaso made")
	default:
		say("Docker stays, if it's there: Kevaso's containers and volumes go (by label); daemon.json goes only if it is still Kevaso's")
	}

	vgBefore := in.Record != nil && in.Record.VGBefore
	// K-114: volumes on Kevaso's own storage with no silo here are no silo's that --force was
	// given for: kept copies, a disk left by a silo deleted elsewhere, or a volume group that
	// couldn't be read. They go only when the person says so.
	// Labelled docker and podman volumes with no silo here are the same leftover (a kept copy's
	// volume, or one whose list could not be read). They go only with --wipe-storage.
	if len(in.Silos) == 0 && !f.WipeStorage && (len(in.EngineVolumes) > 0 || in.EngineVolumesUnknown) {
		what := strings.Join(in.EngineVolumes, ", ")
		if in.EngineVolumesUnknown {
			what = "labelled docker or podman volumes that could not be listed"
			if len(in.EngineVolumes) > 0 {
				what = strings.Join(in.EngineVolumes, ", ") + ", and others that could not be listed"
			}
		}
		return Decision{}, fmt.Errorf("%w: %s, with no silo on this host using them (a kept copy's). Reset with --wipe-storage to remove them with the rest",
			ErrStrayVolumes, what)
	}
	strayLoop := len(in.Silos) == 0 && !f.WipeStorage && !vgBefore &&
		(len(in.PVs) == 0 && in.StorageFile != "" || in.OnLoopFile() && len(in.Volumes) > 0)
	if strayLoop {
		what := strings.Join(in.Volumes, ", ")
		if len(in.PVs) == 0 {
			what = "whatever is in " + in.StorageFile + " (its volume group couldn't be read)"
		}
		return Decision{}, fmt.Errorf("%w: %s, on Kevaso's storage file, with no silo on this host using them (a kept copy's, or a deleted silo's disk). Look at them first (lvs %s); reset with --wipe-storage to remove them with the rest",
			ErrStrayVolumes, what, VG)
	}
	switch {
	case len(in.PVs) == 0 && in.StorageFile != "":
		// A storage file whose volume group can't be seen (it didn't attach): never "stray".
		d.Plan.Storage = StorageLoop
		d.Lost = append(d.Lost, "the storage file "+in.StorageFile+" (its volume group couldn't be read: every microVM disk and volume in it)")
		say("remove Kevaso's storage file %s: its volume group couldn't be read, so whatever disks and volumes are in it go with it", in.StorageFile)
	case len(in.PVs) == 0:
		d.Plan.Storage = StorageLoop // no volume group, no storage file
	case in.OnLoopFile() && !vgBefore:
		d.Plan.Storage = StorageLoop
		d.Lost = append([]string(nil), in.Volumes...)
		if in.StorageFile != "" {
			d.Lost = append(d.Lost, "the storage file "+in.StorageFile)
		}
		say("remove the volume group %s on Kevaso's loop file %s, with its volumes: %s", VG, StorageImage, orNone(in.Volumes))
	case f.WipeStorage:
		d.Plan.Storage = StorageWipe
		d.Lost = append([]string(nil), in.Volumes...)
		say("WIPE the volume group %s on %s (--wipe-storage), with every volume on it: %s", VG, pvNames(in.PVs), orNone(in.Volumes))
	default:
		d.Plan.Storage = StorageKeep
		d.Checks.KeepVG = true
		why := "it sits on " + pvNames(in.PVs) + ", not Kevaso's loop file"
		if vgBefore {
			why = "it was there before Kevaso"
		}
		say("KEEP the volume group %s (%s) and its volumes %s; --wipe-storage removes them", VG, why, orNone(in.Volumes))
	}
	if len(in.EngineVolumes) > 0 {
		d.Lost = append(d.Lost, in.EngineVolumes...)
		say("remove labelled docker and podman volumes: %s", strings.Join(in.EngineVolumes, ", "))
	}
	if in.Installed {
		say("the cluster still lists this host until you run kvoadm host remove for it")
	}
	return d, nil
}

func orNone(ss []string) string {
	if len(ss) == 0 {
		return "(none)"
	}
	return strings.Join(ss, ", ")
}

func pvNames(pvs []PV) string {
	var n []string
	for _, p := range pvs {
		n = append(n, p.Device)
	}
	return strings.Join(n, ", ")
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}
