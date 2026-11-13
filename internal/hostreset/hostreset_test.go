package hostreset

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
)

var fresh = State{
	Packages:  []string{"bash", "iproute2", "lvm2", "nftables", "openssh-server", "systemd"},
	Tables:    []string{"inet provider"},
	IPForward: "0",
}

func TestStateRoundTrip(t *testing.T) {
	got, err := ParseState(fresh.Render())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Packages, fresh.Packages) || !slices.Equal(got.Tables, fresh.Tables) || got.IPForward != fresh.IPForward {
		t.Fatalf("round trip: %+v", got)
	}
	s, err := ParseState("== packages\nbash\n== tables\ninet   kevaso\n== ipforward\n1\n")
	if err != nil || !slices.Equal(s.Tables, []string{"inet kevaso"}) {
		t.Fatalf("got %+v %v", s, err)
	}
}

func TestParseStateRefusesWhatItCantTrust(t *testing.T) {
	for name, out := range map[string]string{
		"empty":            "",
		"no tables":        "== packages\nbash\n== ipforward\n0\n",
		"no packages":      "== packages\n== tables\n== ipforward\n0\n",
		"odd ip_forward":   "== packages\nbash\n== tables\n== ipforward\nyes\n",
		"text before":      "hello\n== packages\nbash\n== tables\n== ipforward\n0\n",
		"unknown sections": "== packages\nbash\n== tables\n== ipforward\n0\n== other\nx\n",
	} {
		if _, err := ParseState(out); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRecordRoundTrip(t *testing.T) {
	for _, r := range []Record{{State: fresh}, {State: fresh, VGBefore: true, DockerJSONBefore: true}} {
		got, err := ParseRecord(r.Render())
		if err != nil || got.VGBefore != r.VGBefore || got.DockerJSONBefore != r.DockerJSONBefore || !slices.Equal(got.Packages, r.Packages) {
			t.Fatalf("%+v: got %+v %v", r, got, err)
		}
	}
	if _, err := ParseRecord(fresh.Render()); err == nil {
		t.Error("a record without its storage and docker lines was accepted")
	}
	// The script keeps a first record, and records nothing over an older install.
	for _, want := range []string{"if [ -s " + RecordFile + " ]; then echo kept", "echo older", "vg=present", "daemon.json=saved", "cp " + DockerDaemonJSONPath + " " + SavedDockerJSON} {
		if !strings.Contains(RecordScript, want) {
			t.Errorf("RecordScript lacks %q", want)
		}
	}
	if strings.Index(RecordScript, "echo kept") > strings.Index(RecordScript, "echo older") {
		t.Error("RecordScript must keep an existing record before deciding the install is an older one")
	}
}

func TestPurgeableIsWatchedAndNew(t *testing.T) {
	now := fresh
	now.Packages = append(slices.Clone(fresh.Packages), "docker.io", "containerd", "qemu-utils", "linux-image-7.0.0-99-generic", "virtiofsd")
	got := Purgeable(fresh, now)
	want := []string{"containerd", "docker.io", "qemu-utils", "virtiofsd"}
	if !slices.Equal(got, want) {
		t.Fatalf("purgeable %v, want %v (a kernel isn't Kevaso's; lvm2 and nftables were there before)", got, want)
	}
	for _, p := range cloudhypervisor.Packages {
		if !slices.Contains(Watched(), p) {
			t.Errorf("the runtime's package %s isn't watched", p)
		}
	}
}

func TestLeftoversNameEveryDifference(t *testing.T) {
	if l := Leftovers(fresh, fresh); len(l) != 0 {
		t.Fatalf("a fresh machine has leftovers: %v", l)
	}
	now := State{
		Packages:  []string{"bash", "docker.io", "iproute2", "nftables", "openssh-server", "systemd"},
		Tables:    []string{"bridge kevaso", "inet provider"},
		IPForward: "1",
	}
	got := strings.Join(Leftovers(fresh, now), "\n")
	for _, want := range []string{"package still installed: docker.io", "nftables table still there: bridge kevaso",
		"package of the record missing: lvm2", "net.ipv4.ip_forward is 1, was 0"} {
		if !strings.Contains(got, want) {
			t.Errorf("leftovers miss %q:\n%s", want, got)
		}
	}
}

func stepIndex(t *testing.T, steps []Step, prefix string) int {
	t.Helper()
	for i, s := range steps {
		if strings.HasPrefix(s.Name, prefix) {
			return i
		}
	}
	t.Fatalf("no step %q in %v", prefix, names(steps))
	return -1
}

func hasStep(steps []Step, prefix string) bool {
	return slices.ContainsFunc(steps, func(s Step) bool { return strings.HasPrefix(s.Name, prefix) })
}

func names(steps []Step) []string {
	var n []string
	for _, s := range steps {
		n = append(n, s.Name)
	}
	return n
}

var full = PlanInput{Purge: []string{"docker.io"}, Tables: []string{"inet kevaso"}, IPForward: "0", DockerOurs: true, Storage: StorageLoop}

func TestPlanOrder(t *testing.T) {
	steps := Plan(full)
	order := []string{
		"stop kevasod", "stop every kevaso-*", "kill what is left",
		"remove containers", "stop docker",
		"delete links", "delete docker0", "delete addresses", "delete nftables tables", "restore net.ipv4.ip_forward",
		"remove volume group", "purge docker.io",
		"unmount what is mounted", "remove Kevaso's files", "remove the tests' /etc/hosts", "remove kevaso-* users",
	}
	last := -1
	for _, p := range order {
		i := stepIndex(t, steps, p)
		if i <= last {
			t.Errorf("step %q at %d, before the step it must follow (%v)", p, i, names(steps))
		}
		last = i
	}
	if len(steps) != len(order) {
		t.Errorf("%d steps, the order test knows %d: %v", len(steps), len(order), names(steps))
	}
}

func TestPlanLeavesDockerThatWasThereBefore(t *testing.T) {
	steps := Plan(PlanInput{IPForward: "0", RestoreDockerJSON: true})
	for _, bad := range []string{"remove containers, volumes and images", "stop docker", "delete docker0", "purge"} {
		if hasStep(steps, bad) {
			t.Errorf("Docker isn't Kevaso's, but the plan has %q", bad)
		}
	}
	c := steps[stepIndex(t, steps, "remove Kevaso's containers")].Script
	if !strings.Contains(c, "--filter label=kevaso.com/uid") || strings.Contains(c, "system prune") {
		t.Errorf("containers step: %q", c)
	}
	if s := steps[stepIndex(t, steps, "restore Docker's daemon.json")].Script; !strings.Contains(s, "cp "+SavedDockerJSON+" "+DockerDaemonJSONPath) {
		t.Errorf("restore step: %q", s)
	}
	files := steps[stepIndex(t, steps, "remove Kevaso's files")].Script
	for _, p := range DockerPaths {
		if strings.Contains(files, p) {
			t.Errorf("Docker isn't Kevaso's, but %s is removed", p)
		}
	}
	// Without a saved daemon.json, Kevaso's own is removed only if unchanged.
	steps = Plan(PlanInput{})
	s := steps[stepIndex(t, steps, "remove Kevaso's daemon.json")].Script
	if !strings.Contains(s, "cmp -s - "+DockerDaemonJSONPath+" && rm -f "+DockerDaemonJSONPath) {
		t.Errorf("daemon.json step: %q", s)
	}
	if hasStep(steps, "restore net.ipv4") {
		t.Error("no record: IP forwarding must be left as it is")
	}
}

func TestPlanPurgesOnlyWhatItIsGiven(t *testing.T) {
	for _, s := range Plan(PlanInput{IPForward: "0", DockerOurs: true}) {
		if strings.Contains(s.Script, "apt-get") {
			t.Errorf("no packages to purge, but step %q runs apt-get", s.Name)
		}
	}
	steps := Plan(PlanInput{Purge: []string{"docker.io", "bad;rm -rf /"}, IPForward: "0"})
	p := steps[stepIndex(t, steps, "purge")]
	if !strings.Contains(p.Script, "apt-get purge -y -qq docker.io &&") || strings.Contains(p.Script, "bad") {
		t.Errorf("purge step: %q", p.Script)
	}
}

func TestPlanDeletesOnlyTheTablesItIsGiven(t *testing.T) {
	steps := Plan(PlanInput{Tables: []string{"inet kevaso", "bridge kevaso", "inet x; reboot", "ip"}, IPForward: "0"})
	s := steps[stepIndex(t, steps, "delete nftables tables")].Script
	if !strings.Contains(s, "nft delete table inet kevaso\n") || !strings.Contains(s, "nft delete table bridge kevaso\n") {
		t.Errorf("tables step: %q", s)
	}
	if strings.Contains(s, "reboot") || strings.Count(s, "nft delete") != 2 {
		t.Errorf("an unsafe or malformed table name reached the script: %q", s)
	}
	for in, want := range map[string]string{"1": "=1", "0": "=0"} {
		steps := Plan(PlanInput{IPForward: in})
		if got := steps[stepIndex(t, steps, "restore")].Script; !strings.HasSuffix(got, "ip_forward"+want) {
			t.Errorf("ip_forward %q: %q", in, got)
		}
	}
	if hasStep(Plan(PlanInput{IPForward: "1; reboot"}), "restore net.ipv4") {
		t.Error("an odd ip_forward value reached the plan")
	}
}

var rmArgs = regexp.MustCompile(`(?m)^\s*rm -(?:rf|f) ([^\n;&|]+)`)

func TestPlanRemovesFilesOnlyUnderKevasosPaths(t *testing.T) {
	n := 0
	for _, in := range []PlanInput{full, {Storage: StorageWipe}, {}} {
		for _, s := range Plan(in) {
			for _, m := range rmArgs.FindAllStringSubmatch(s.Script, -1) {
				for _, p := range strings.Fields(m[1]) {
					n++
					if !underAllowed(p) {
						t.Errorf("step %q removes %q, outside Kevaso's paths", s.Name, p)
					}
				}
			}
		}
	}
	if n < len(Paths)+len(DockerPaths) {
		t.Errorf("found %d removed paths, want at least %d", n, len(Paths)+len(DockerPaths))
	}
	for _, p := range append(slices.Clone(Paths), DockerPaths...) {
		if !underAllowed(p) {
			t.Errorf("%q is outside the allowed roots", p)
		}
	}
	if !strings.HasPrefix(RecordFile, "/var/lib/kevaso-") {
		t.Error("the record isn't removed with Kevaso's files")
	}
}

func underAllowed(p string) bool {
	if p == StorageImage {
		return true
	}
	for _, r := range AllowedRoots {
		if strings.HasPrefix(p, r) && len(p) > len(r) || p == r {
			return true
		}
	}
	return false
}

func TestPlanStorage(t *testing.T) {
	keep := Plan(PlanInput{Storage: StorageKeep})
	for _, s := range keep {
		for _, bad := range []string{"lvremove", "vgremove", "pvremove", StorageImage} {
			if strings.Contains(s.Script, bad) {
				t.Errorf("keeping storage, step %q contains %q", s.Name, bad)
			}
		}
	}
	loop := Plan(PlanInput{Storage: StorageLoop})
	s := loop[stepIndex(t, loop, "remove volume group")].Script
	for _, want := range []string{"vg=" + VG + "\n", "refusing: volume group $vg is on $p, a real disk", "[ \"$b\" = " + StorageImage + " ]"} {
		if !strings.Contains(s, want) {
			t.Errorf("loop step lacks %q:\n%s", want, s)
		}
	}
	wipe := Plan(PlanInput{Storage: StorageWipe})
	w := wipe[stepIndex(t, wipe, "wipe volume group")].Script
	if !strings.Contains(w, "vg="+VG+"\n") || strings.Contains(w, "refusing") || !strings.Contains(w, `pvremove -qq -fy "$p"`) {
		t.Errorf("wipe step:\n%s", w)
	}
	for _, in := range []PlanInput{{Storage: StorageLoop}, {Storage: StorageWipe}} {
		for _, st := range Plan(in) {
			if strings.Contains(st.Script, "vgremove") && !strings.Contains(st.Script, "vg="+VG+"\n") {
				t.Errorf("step %q removes a volume group other than %s", st.Name, VG)
			}
		}
	}
}

func TestPlanNeverStopsSSH(t *testing.T) {
	for _, in := range []PlanInput{full, {Storage: StorageWipe}, {}} {
		for _, s := range Plan(in) {
			for _, bad := range []string{"ssh", "reboot", "poweroff", "iptables -F", "nft flush ruleset", "/etc/ssh"} {
				if strings.Contains(s.Script, bad) {
					t.Errorf("step %q contains %q", s.Name, bad)
				}
			}
		}
	}
}

func TestChecklistCoversThePlan(t *testing.T) {
	all := ""
	for _, c := range Checklist(CheckOptions{Ports: []int{6443, 18080}, DockerGone: true}) {
		all += c.Script + "\n"
	}
	for _, p := range append(slices.Clone(Paths), DockerPaths...) {
		if !strings.Contains(all, p) {
			t.Errorf("no check looks for %s", p)
		}
	}
	for _, p := range append(slices.Clone(Processes), DockerProcesses...) {
		if !strings.Contains(all, p) {
			t.Errorf("no check looks for the process %s", p)
		}
	}
	for _, want := range []string{"6443", "18080", "vgs", "losetup", "dmsetup", HostsMarker, "kevaso-", "kvbr", "docker0", "/proc/mounts", "nft list tables", "command -v docker"} {
		if !strings.Contains(all, want) {
			t.Errorf("no check mentions %q", want)
		}
	}
	kept := ""
	for _, c := range Checklist(CheckOptions{KeepVG: true}) {
		kept += c.Script + "\n"
	}
	for _, bad := range []string{"vgs --noheadings", "dmsetup", "command -v docker containerd", "/var/lib/docker", "docker0"} {
		if strings.Contains(kept, bad) {
			t.Errorf("a checklist keeping the volume group and Docker still checks %q", bad)
		}
	}
}

func TestReport(t *testing.T) {
	checks := []Check{{"a", "x"}, {"b", "y"}}
	if err := Report(checks, map[string]string{"a": "\n", "b": ""}, nil); err != nil {
		t.Fatalf("clean: %v", err)
	}
	err := Report(checks, map[string]string{"a": "kvbr0\nkvt123\n"}, []string{"package still installed: docker.io"})
	if !errors.Is(err, ErrNotClean) || !strings.Contains(err.Error(), "a: kvbr0, kvt123") || !strings.Contains(err.Error(), "docker.io") || strings.Contains(err.Error(), "b:") {
		t.Fatalf("got %v", err)
	}
}
