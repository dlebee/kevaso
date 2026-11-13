// Package hostreset takes what Kevaso installed on a host off it again, so the machine can be
// reused without reinstalling its OS (kvoadm reset; the metal test machine's reset). It is pure:
// shell scripts to run as root and functions that read their output. Running them is the
// caller's (over SSH).
//
//   - The install record: what the host looked like before Kevaso was installed (its packages,
//     nftables tables, IP forwarding, whether the kevaso volume group already existed, Docker's
//     daemon.json), written once by kvoadm before it installs anything (RecordScript).
//   - Inspect: the host now (InspectScript, ParseInspection): the record, whether Kevaso is
//     installed, the silos on it, the volume group and what it sits on.
//   - Decide: from the inspection and the operator's flags, the plan's input, what to tell the
//     operator, or why not to go ahead (a host with silos, unless forced).
//   - Plan: the steps, in order. Checklist: what must be gone afterwards, each check printing
//     what's left. Leftovers: the difference between the record and the host after the plan.
//
// Without a record (an install older than the record), the plan falls back to fixed lists:
// Kevaso's own units, files, links, users and kevaso* tables, its containers by label, and the
// volume group on Kevaso's own loop file; no package is purged and IP forwarding is left as it is.
package hostreset

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/container"
)

// Paths on the host.
const (
	// RecordDir holds the install record. It is under /var/lib/kevaso-*, so the reset removes it
	// with the rest, after reading it.
	RecordDir  = "/var/lib/kevaso-install"
	RecordFile = RecordDir + "/record"
	// SavedDockerJSON is Docker's daemon.json as it was before Kevaso wrote its own.
	SavedDockerJSON = RecordDir + "/docker-daemon.json"
	// StorageImage is the loop file --loop-storage backs the volume group with.
	StorageImage = "/var/lib/kevaso-storage.img"
	// HostsMarker ends every /etc/hosts line Kevaso's tests add; the reset removes those lines.
	HostsMarker = "# kvt-e2e"
	// TestUnitPrefix starts the transient units Kevaso's tests start (systemd-run --unit=kvt-…).
	TestUnitPrefix = "kvt-"
	// DockerDaemonJSONPath is where Kevaso writes Docker's configuration.
	DockerDaemonJSONPath = "/etc/docker/daemon.json"
)

// VG is the volume group Kevaso's microVM runtime uses.
const VG = cloudhypervisor.VG

// Paths are Kevaso's own files, removed by every reset. Each is under one of AllowedRoots.
var Paths = []string{
	"/usr/local/bin/kevasod", "/usr/local/bin/kevaso-plugin-*",
	"/etc/kevaso", "/etc/kevaso-silos.nft", "/etc/profile.d/kevaso-secrets.sh",
	"/etc/systemd/system/kevasod.service", "/etc/systemd/system/kevaso-*.service", "/etc/systemd/system/kevaso-*.d",
	"/opt/kevaso",
	"/var/lib/kevaso", "/var/lib/kevaso-*", "/var/cache/kevaso",
	"/run/kevaso", "/run/kevaso-*",
}

// DockerPaths are Docker's own directories, removed only when Kevaso installed Docker.
var DockerPaths = []string{"/var/lib/docker", "/var/lib/containerd", "/etc/docker"}

// PodmanPaths are podman's storage, removed only when Kevaso installed podman (its configuration
// in /etc/containers goes with the package).
var PodmanPaths = []string{"/var/lib/containers"}

// AllowedRoots are the only places the plan removes files under.
var AllowedRoots = []string{"/usr/local/bin/kevaso", "/etc/kevaso", "/etc/docker", "/etc/profile.d/kevaso-", "/etc/systemd/system/kevaso",
	"/opt/kevaso", "/var/lib/kevaso", "/var/cache/kevaso", "/run/kevaso", "/var/lib/docker", "/var/lib/containerd", "/var/lib/containers"}

// mountPattern matches mount points under Kevaso's paths (an extended regular expression).
const mountPattern = `^/(var/lib/kevaso|run/kevaso|var/lib/docker|var/lib/containerd|var/lib/containers|opt/kevaso)`

// Processes that must not outlive a reset (pgrep -x names; the kernel keeps 15 characters).
var Processes = []string{"kevasod", "cloud-hypervisor", "ch-remote", "virtiofsd"}

// DockerProcesses must not outlive a reset that removed Docker.
var DockerProcesses = []string{"dockerd", "containerd", "containerd-shim-runc-v2"}

// PodmanProcesses must not outlive a reset that removed podman (conmon watches each container).
var PodmanProcesses = []string{"conmon"}

// dockerDeps are what docker.io pulls in on Ubuntu, purged with it when the record shows they
// weren't there before.
var dockerDeps = []string{"containerd", "runc", "bridge-utils", "pigz", "ubuntu-fan", "docker-buildx", "docker-compose-v2"}

// Watched are the packages Kevaso's runtimes install (and their dependencies): a reset purges
// those its record didn't have. Others that appeared meanwhile (a kernel unattended-upgrades
// installed) aren't Kevaso's and are left alone.
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

// State is what a reset compares with the record.
type State struct {
	Packages  []string // installed packages (dpkg "ii")
	Tables    []string // nftables tables, "FAMILY NAME"
	IPForward string   // net.ipv4.ip_forward
}

// StateScript prints the host's State in sections (ParseState reads it).
const StateScript = `echo '== packages'
dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1 == "ii" {print $2}' | sort -u
echo '== tables'
nft list tables 2>/dev/null | awk '$1 == "table" {print $2, $3}' | sort -u
echo '== ipforward'
sysctl -n net.ipv4.ip_forward
`

// sections splits "== NAME" sectioned output; text before the first section is an error.
func sections(out string) (map[string][]string, error) {
	got := map[string][]string{}
	section := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "== ") {
			section = strings.TrimPrefix(line, "== ")
			if _, ok := got[section]; !ok {
				got[section] = nil
			}
			continue
		}
		if section == "" {
			return nil, fmt.Errorf("a line outside any section: %q", line)
		}
		got[section] = append(got[section], line)
	}
	return got, nil
}

// ParseState reads StateScript's output.
func ParseState(out string) (State, error) {
	sec, err := sections(out)
	if err != nil {
		return State{}, fmt.Errorf("state: %w", err)
	}
	for name := range sec {
		if name != "packages" && name != "tables" && name != "ipforward" {
			return State{}, fmt.Errorf("state: unknown section %q", name)
		}
	}
	return stateFrom(sec)
}

func stateFrom(sec map[string][]string) (State, error) {
	for _, want := range []string{"packages", "tables", "ipforward"} {
		if _, ok := sec[want]; !ok {
			return State{}, fmt.Errorf("state: no %q section", want)
		}
	}
	s := State{Packages: sec["packages"]}
	for _, t := range sec["tables"] {
		s.Tables = append(s.Tables, strings.Join(strings.Fields(t), " "))
	}
	if len(s.Packages) == 0 {
		return State{}, errors.New("state: no packages (not a Debian or Ubuntu machine?)")
	}
	if f := sec["ipforward"]; len(f) == 1 {
		s.IPForward = f[0]
	}
	if s.IPForward != "0" && s.IPForward != "1" {
		return State{}, fmt.Errorf("state: ip_forward %q", s.IPForward)
	}
	return s, nil
}

// Render is State in StateScript's format.
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

// Record is the install record: the host before Kevaso.
type Record struct {
	State
	VGBefore         bool // the kevaso volume group already existed: it isn't Kevaso's to remove
	DockerJSONBefore bool // Docker had a daemon.json, saved in SavedDockerJSON
}

// RecordScript writes the install record before anything of Kevaso's is installed. A second
// install keeps the first one's record ("kept"); a host where Kevaso is installed already with no
// record (an older install) gets none, since it would take in Kevaso's own changes ("older").
// Otherwise it prints "recorded".
const RecordScript = `set -e
if [ -s ` + RecordFile + ` ]; then echo kept; exit 0; fi
if [ -e /usr/local/bin/kevasod ] || [ -e /etc/systemd/system/kevasod.service ]; then echo older; exit 0; fi
umask 077
mkdir -p ` + RecordDir + `
{
` + StateScript + `echo '== storage'
if vgs ` + VG + ` >/dev/null 2>&1; then echo vg=present; else echo vg=absent; fi
echo '== docker'
if [ -f ` + DockerDaemonJSONPath + ` ]; then cp ` + DockerDaemonJSONPath + ` ` + SavedDockerJSON + `; echo daemon.json=saved; else echo daemon.json=absent; fi
} > ` + RecordFile + `.tmp
mv ` + RecordFile + `.tmp ` + RecordFile + `
echo recorded
`

// ParseRecord reads a record file.
func ParseRecord(out string) (Record, error) {
	sec, err := sections(out)
	if err != nil {
		return Record{}, fmt.Errorf("record: %w", err)
	}
	st, err := stateFrom(sec)
	if err != nil {
		return Record{}, fmt.Errorf("record: %w", err)
	}
	r := Record{State: st}
	switch {
	case slices.Contains(sec["storage"], "vg=present"):
		r.VGBefore = true
	case slices.Contains(sec["storage"], "vg=absent"):
	default:
		return Record{}, errors.New("record: no storage line")
	}
	switch {
	case slices.Contains(sec["docker"], "daemon.json=saved"):
		r.DockerJSONBefore = true
	case slices.Contains(sec["docker"], "daemon.json=absent"):
	default:
		return Record{}, errors.New("record: no docker line")
	}
	return r, nil
}

// Render is the record in its file's format.
func (r Record) Render() string {
	vg, dj := "absent", "absent"
	if r.VGBefore {
		vg = "present"
	}
	if r.DockerJSONBefore {
		dj = "saved"
	}
	return r.State.Render() + "== storage\nvg=" + vg + "\n== docker\ndaemon.json=" + dj + "\n"
}

// Purgeable are the watched packages installed now that base didn't have.
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

// ExtraTables are the nftables tables now that base didn't have.
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

// KevasoTables are the tables named kevaso* (the fallback without a record).
func KevasoTables(now State) []string {
	var out []string
	for _, t := range now.Tables {
		if f := strings.Fields(t); len(f) == 2 && strings.HasPrefix(f[1], "kevaso") {
			out = append(out, t)
		}
	}
	return out
}

// Leftovers compares the host with base: watched packages added, tables added, packages base had
// that are gone (a purge took too much), IP forwarding changed.
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
			out = append(out, "package of the record missing: "+p)
		}
	}
	if base.IPForward != now.IPForward {
		out = append(out, fmt.Sprintf("net.ipv4.ip_forward is %s, was %s", now.IPForward, base.IPForward))
	}
	return out
}

// Storage is what the plan does with the volume group.
type Storage int

const (
	// StorageKeep leaves the volume group and every volume on it alone.
	StorageKeep Storage = iota
	// StorageLoop removes it, only when it sits on StorageImage alone (refused otherwise, on the host).
	StorageLoop
	// StorageWipe removes it and its volumes wherever it sits, real disks included (--wipe-storage).
	StorageWipe
)

// Step is one thing a reset does: a root shell script. A failed step doesn't stop the reset
// (everything is tried); the checklist decides whether the host is clean.
type Step struct {
	Name   string
	Script string
}

// PlanInput is what the plan needs to know.
type PlanInput struct {
	Purge      []string // packages to purge
	Tables     []string // nftables tables to delete, "FAMILY NAME"
	IPForward  string   // the record's value; "" leaves it as it is
	DockerOurs bool     // Kevaso installed Docker: every container and image goes, then Docker itself
	PodmanOurs bool     // Kevaso installed podman: every container, image and its storage go
	// RestoreDockerJSON puts back the daemon.json Docker had before (when Docker stays).
	RestoreDockerJSON bool
	Storage           Storage
}

// Plan is the reset, in order. Pure.
func Plan(in PlanInput) []Step {
	var steps []Step
	add := func(name, script string) { steps = append(steps, Step{name, script}) }

	// 1. Nothing restarts anything: kevasod and the fence first, then every silo, gateway and
	// plugin unit, then the tests' transient units.
	add("stop kevasod and the fence", `systemctl disable --now kevasod.service kevaso-fence.service 2>/dev/null; true`)
	add("stop every kevaso-* and "+TestUnitPrefix+"* unit", `for u in $(systemctl list-units --all --plain --no-legend 'kevaso*' '`+TestUnitPrefix+`*' | awk '{print $1}'); do
  systemctl disable --now "$u" 2>/dev/null; systemctl kill -s KILL "$u" 2>/dev/null
done
for f in /etc/systemd/system/kevaso*.service; do [ -e "$f" ] && systemctl disable "$(basename "$f")" 2>/dev/null; done
true`)
	add("kill what is left", `for p in `+strings.Join(Processes, " ")+`; do pkill -KILL -x "$(printf %.15s "$p")"; done; sleep 1; true`)

	// 2. Containers: all of them when Docker is Kevaso's; otherwise only Kevaso's, by label.
	if in.DockerOurs {
		add("remove containers, volumes and images", `if command -v docker >/dev/null && systemctl is-active -q docker; then
  ids=$(docker ps -aq); [ -z "$ids" ] || docker rm -f $ids >/dev/null
  vs=$(docker volume ls -q); [ -z "$vs" ] || docker volume rm -f $vs >/dev/null
  docker system prune -af --volumes >/dev/null
fi
true`)
		add("stop docker", `systemctl disable --now docker.socket docker.service containerd.service 2>/dev/null; true`)
	} else {
		add("remove Kevaso's containers and volumes (by label)", `if command -v docker >/dev/null && systemctl is-active -q docker; then
  ids=$(docker ps -aq --filter label=kevaso.com/uid); [ -z "$ids" ] || docker rm -f $ids >/dev/null
  vs=$(docker volume ls -q --filter label=kevaso.com/uid); [ -z "$vs" ] || docker volume rm -f $vs >/dev/null
fi
true`)
	}

	// Podman has no daemon: its containers are conmon processes, stopped here.
	if in.PodmanOurs {
		add("remove podman's containers, volumes and images", `if command -v podman >/dev/null; then
  podman rm -af -t 0 >/dev/null 2>&1; podman pod rm -af >/dev/null 2>&1; podman volume rm -af >/dev/null 2>&1
  podman system reset -f >/dev/null 2>&1
fi
true`)
	} else {
		add("remove Kevaso's podman containers and volumes (by label)", `if command -v podman >/dev/null; then
  ids=$(podman ps -aq --filter label=kevaso.com/uid); [ -z "$ids" ] || podman rm -f -t 0 $ids >/dev/null
  vs=$(podman volume ls -q --filter label=kevaso.com/uid); [ -z "$vs" ] || podman volume rm -f $vs >/dev/null
fi
true`)
	}

	// 3. The network.
	add("delete links (kvbr*, kvt*, kevaso*)", `for l in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
  case "$l" in kvbr*|kvt*|kevaso*) ip link del "$l";; esac
done
true`)
	if in.DockerOurs {
		add("delete docker0", `ip link show docker0 >/dev/null 2>&1 && ip link del docker0; true`)
	}
	add("delete addresses labelled :kv", `ip -4 -o addr show | awk '$NF ~ /:kv$/ {print $2, $4, $NF}' | while read dev addr label; do ip addr del "$addr" dev "$dev" label "$label"; done; true`)
	var del strings.Builder
	for _, t := range in.Tables {
		f := strings.Fields(t)
		if len(f) == 2 && safeWord(f[0]) && safeWord(f[1]) {
			fmt.Fprintf(&del, "nft delete table %s %s\n", f[0], f[1])
		}
	}
	add("delete nftables tables", del.String()+"true")
	if in.IPForward == "0" || in.IPForward == "1" {
		add("restore net.ipv4.ip_forward", "sysctl -qw net.ipv4.ip_forward="+in.IPForward)
	}

	// 4. Storage.
	switch in.Storage {
	case StorageLoop:
		add("remove volume group "+VG+" (on the loop file only)", `vg=`+VG+`
if vgs "$vg" >/dev/null 2>&1; then
  pvs=$(pvs --noheadings -o pv_name -S vg_name="$vg" | tr -d ' ')
  for p in $pvs; do
    case "$p" in
    /dev/loop*) b=$(losetup -n -O BACK-FILE "$p" | tr -d ' ')
      [ "$b" = `+StorageImage+` ] || { echo "refusing: volume group $vg is on $p ($b), not `+StorageImage+`" >&2; exit 1; } ;;
    *) echo "refusing: volume group $vg is on $p, a real disk (--wipe-storage removes it)" >&2; exit 1 ;;
    esac
  done
  lvremove -qq -fy "$vg"; vgremove -qq -fy "$vg"
  for p in $pvs; do pvremove -qq -fy "$p"; done
fi
for d in $(losetup -n -O NAME -j `+StorageImage+`); do losetup -d "$d"; done
rm -f `+StorageImage)
	case StorageWipe:
		add("wipe volume group "+VG+" and every volume on it", `vg=`+VG+`
if vgs "$vg" >/dev/null 2>&1; then
  pvs=$(pvs --noheadings -o pv_name -S vg_name="$vg" | tr -d ' ')
  lvremove -qq -fy "$vg"; vgremove -qq -fy "$vg"
  for p in $pvs; do pvremove -qq -fy "$p"; done
fi
for d in $(losetup -n -O NAME -j `+StorageImage+`); do losetup -d "$d"; done
rm -f `+StorageImage)
	}

	// 5. Packages Kevaso installed, then what came with them.
	var ok []string
	for _, p := range in.Purge {
		if safeWord(p) {
			ok = append(ok, p)
		}
	}
	if len(ok) > 0 {
		add("purge "+strings.Join(ok, " "), "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "+strings.Join(ok, " ")+
			" && DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y -qq")
	}

	// 6. Docker's configuration, files, the tests' /etc/hosts lines, users.
	if !in.DockerOurs {
		if in.RestoreDockerJSON {
			add("restore Docker's daemon.json", `[ -f `+SavedDockerJSON+` ] && cp `+SavedDockerJSON+` `+DockerDaemonJSONPath+` && (systemctl try-restart docker || true)`)
		} else {
			add("remove Kevaso's daemon.json (only if it is still Kevaso's)", `[ -f `+DockerDaemonJSONPath+` ] && printf '%s' `+shQuote(container.DockerDaemonJSON)+` | cmp -s - `+DockerDaemonJSONPath+` && rm -f `+DockerDaemonJSONPath+` && (systemctl try-restart docker || true); true`)
		}
	}
	add("unmount what is mounted under Kevaso's paths", `awk '{print $2}' /proc/mounts | grep -E '`+mountPattern+`' | sort -r | while read m; do umount -l "$m"; done; true`)
	files := slices.Clone(Paths)
	if in.DockerOurs {
		files = append(files, DockerPaths...)
	}
	if in.PodmanOurs {
		files = append(files, PodmanPaths...)
	}
	add("remove Kevaso's files", "rm -rf "+strings.Join(files, " ")+"\nsystemctl daemon-reload; systemctl reset-failed; true")
	add("remove the tests' /etc/hosts lines", `sed -i '/`+HostsMarker+`$/d' /etc/hosts`)
	add("remove kevaso-* users", `for u in $(awk -F: '$1 ~ /^kevaso-/ {print $1}' /etc/passwd); do userdel "$u"; done
for g in $(awk -F: '$1 ~ /^kevaso-/ {print $1}' /etc/group); do groupdel "$g"; done
true`)
	return steps
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

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

// Check is one checklist item: a script that prints what is left (nothing: clean) and exits 0.
type Check struct {
	Name   string
	Script string
}

// CheckOptions say what the checklist expects gone.
type CheckOptions struct {
	Ports      []int // TCP ports nothing may listen on (except on loopback)
	DockerGone bool  // Docker was Kevaso's: it must be gone too
	PodmanGone bool  // podman was Kevaso's: it must be gone too
	KeepVG     bool  // the volume group was kept on purpose: don't report it
}

// KevasoPorts are the TCP ports kevasod listens on.
var KevasoPorts = []int{2379, 2380, 6443}

// Checklist is everything that must be gone after a reset. Pure.
func Checklist(o CheckOptions) []Check {
	var portList []string
	for _, p := range o.Ports {
		portList = append(portList, fmt.Sprint(p))
	}
	procs := slices.Clone(Processes)
	files := slices.Clone(Paths)
	links := "kvbr|kvt|kevaso"
	if o.DockerGone {
		procs = append(procs, DockerProcesses...)
		files = append(files, DockerPaths...)
		links += "|docker0"
	}
	if o.PodmanGone {
		procs = append(procs, PodmanProcesses...)
		files = append(files, PodmanPaths...)
	}
	checks := []Check{
		{"no Kevaso unit is loaded", `systemctl list-units --all --plain --no-legend 'kevaso*' '` + TestUnitPrefix + `*' | awk '{print $1}'`},
		{"no Kevaso process runs", `for p in ` + strings.Join(procs, " ") + `; do pgrep -x "$(printf %.15s "$p")" >/dev/null && echo "$p"; done; true`},
		{"no Kevaso file is left", `for f in ` + strings.Join(files, " ") + `; do [ -e "$f" ] && echo "$f"; done; true`},
		{"nothing is mounted under Kevaso's paths", `awk '{print $2}' /proc/mounts | grep -E '` + mountPattern + `'; true`},
		{"no Kevaso link is left", `ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(` + links + `)'; true`},
		{"no :kv address is left", `ip -4 -o addr show | awk '$NF ~ /:kv$/ {print $2, $4}'`},
		{"no nftables table named kevaso*", `nft list tables 2>/dev/null | awk '$3 ~ /^kevaso/ {print $2, $3}'`},
		{"no Kevaso container", `command -v docker >/dev/null && systemctl is-active -q docker && docker ps -aq --filter label=kevaso.com/uid
command -v podman >/dev/null && podman ps -aq --filter label=kevaso.com/uid; true`},
		{"no loop device on " + StorageImage, `losetup -n -O NAME -j ` + StorageImage + ` 2>/dev/null`},
		{"no kevaso-* user or group", `awk -F: '$1 ~ /^kevaso-/ {print "user " $1}' /etc/passwd; awk -F: '$1 ~ /^kevaso-/ {print "group " $1}' /etc/group`},
		{"no test line in /etc/hosts", `grep -F -e '` + HostsMarker + `' /etc/hosts; true`},
		{"nothing listens on Kevaso's ports", `ss -Htlnu | awk '{print $5}' | while read a; do p=${a##*:}; h=${a%:*}
  case "$h" in 127.*|\[::1\]) continue;; esac
  for w in ` + strings.Join(portList, " ") + `; do [ "$p" = "$w" ] && echo "$a"; done
done; true`},
	}
	if !o.KeepVG {
		checks = append(checks,
			Check{"no volume group " + VG, `vgs --noheadings -o vg_name ` + VG + ` 2>/dev/null | tr -d ' '`},
			Check{"no device-mapper device of " + VG, `dmsetup ls 2>/dev/null | awk '$1 ~ /^` + VG + `-/ {print $1}'`})
	}
	if o.DockerGone {
		checks = append(checks, Check{"no docker", `command -v docker containerd dockerd 2>/dev/null; true`})
	}
	if o.PodmanGone {
		checks = append(checks, Check{"no podman", `command -v podman conmon 2>/dev/null; true`})
	}
	return checks
}

// Report puts a checklist's outputs (by check name) and the record comparison's leftovers into
// one error naming every leftover, or nil when clean. Pure.
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
var ErrNotClean = errors.New("the host is not clean after the reset")
