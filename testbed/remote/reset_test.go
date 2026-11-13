package remote

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
	// Tables are normalized to "FAMILY NAME" whatever the spacing.
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

func TestPurgeableIsWatchedAndNew(t *testing.T) {
	now := fresh
	now.Packages = append(slices.Clone(fresh.Packages), "docker.io", "containerd", "qemu-utils", "linux-image-6.8.0-99-generic", "virtiofsd")
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
	if !slices.Contains(Watched(), "docker.io") {
		t.Error("docker.io isn't watched")
	}
}

func TestLeftoversNameEveryDifference(t *testing.T) {
	if l := Leftovers(fresh, fresh); len(l) != 0 {
		t.Fatalf("a fresh machine has leftovers: %v", l)
	}
	now := State{
		Packages:  []string{"bash", "docker.io", "iproute2", "nftables", "openssh-server", "systemd"}, // lvm2 gone, docker.io new
		Tables:    []string{"bridge kevaso", "inet provider"},
		IPForward: "1",
	}
	got := strings.Join(Leftovers(fresh, now), "\n")
	for _, want := range []string{"package still installed: docker.io", "nftables table still there: bridge kevaso",
		"package of the baseline missing: lvm2", "net.ipv4.ip_forward is 1, was 0"} {
		if !strings.Contains(got, want) {
			t.Errorf("leftovers miss %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "inet provider") {
		t.Error("a table of the baseline counted as a leftover")
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

func names(steps []Step) []string {
	var n []string
	for _, s := range steps {
		n = append(n, s.Name)
	}
	return n
}

func TestPlanOrder(t *testing.T) {
	steps := Plan(PlanInput{Purge: []string{"docker.io"}, Tables: []string{"inet kevaso"}, IPForward: "0"})
	order := []string{
		"stop kevasod",                 // nothing restarts silos
		"stop every kevaso-*",          // VMs, gateways, plugins, the tests' units
		"kill what is left",            // a VMM whose unit was already gone
		"remove containers",            // while Docker runs
		"stop docker",                  // before its package goes
		"delete links",                 // the bridge and taps (the VMs are gone)
		"delete addresses",             // ip-pool and endpoint addresses
		"delete nftables tables",       // the firewall
		"restore net.ipv4.ip_forward",  // as it was
		"remove volume group",          // nothing holds an LV open any more
		"purge docker.io",              // then the packages
		"unmount what is mounted",      // before rm -rf
		"remove Kevaso's files",        // then the files
		"remove the tests' /etc/hosts", // and the tests' own lines
		"remove kevaso-* users",        // and the users nothing runs as now
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

func TestPlanPurgesOnlyWhatItIsGiven(t *testing.T) {
	steps := Plan(PlanInput{IPForward: "0"})
	for _, s := range steps {
		if strings.Contains(s.Script, "apt-get") {
			t.Errorf("no packages to purge, but step %q runs apt-get", s.Name)
		}
	}
	steps = Plan(PlanInput{Purge: []string{"docker.io", "bad;rm -rf /"}, IPForward: "0"})
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
	// ip_forward goes back to the baseline's, and only to 0 or 1.
	for in, want := range map[string]string{"1": "=1", "0": "=0", "1; reboot": "=0"} {
		steps := Plan(PlanInput{IPForward: in})
		if got := steps[stepIndex(t, steps, "restore")].Script; !strings.HasSuffix(got, "ip_forward"+want) {
			t.Errorf("ip_forward %q: %q", in, got)
		}
	}
}

var rmArgs = regexp.MustCompile(`(?m)^\s*rm -(?:rf|f) ([^\n;&|]+)`)

func TestPlanRemovesFilesOnlyUnderKevasosPaths(t *testing.T) {
	steps := Plan(PlanInput{Purge: []string{"docker.io"}, Tables: []string{"inet kevaso"}, IPForward: "0"})
	n := 0
	for _, s := range steps {
		for _, m := range rmArgs.FindAllStringSubmatch(s.Script, -1) {
			for _, p := range strings.Fields(m[1]) {
				n++
				if !underAllowed(p) {
					t.Errorf("step %q removes %q, outside Kevaso's paths", s.Name, p)
				}
			}
		}
	}
	if n < len(Paths) {
		t.Errorf("found %d removed paths, want at least the %d in Paths", n, len(Paths))
	}
	for _, p := range Paths {
		if !underAllowed(p) {
			t.Errorf("Paths has %q, outside the allowed roots", p)
		}
		if strings.Contains(p, BaselineDir) {
			t.Errorf("the reset would remove the baseline (%s)", p)
		}
	}
}

func underAllowed(p string) bool {
	if p == StorageImage {
		return true
	}
	for _, r := range allowedRoots {
		if strings.HasPrefix(p, r) && len(p) > len(r) || p == r {
			return true
		}
	}
	return false
}

func TestPlanTouchesOnlyItsVolumeGroupOnItsLoopFile(t *testing.T) {
	steps := Plan(PlanInput{IPForward: "0"})
	s := steps[stepIndex(t, steps, "remove volume group")].Script
	for _, want := range []string{"vg=" + cloudhypervisor.VG + "\n", `vgs "$vg"`, `lvremove -qq -fy "$vg"`, `vgremove -qq -fy "$vg"`,
		"refusing: volume group $vg is on $p, a real disk", "[ \"$b\" = " + StorageImage + " ]", "losetup -n -O NAME -j " + StorageImage} {
		if !strings.Contains(s, want) {
			t.Errorf("volume group step lacks %q:\n%s", want, s)
		}
	}
	// The only volume group named anywhere is Kevaso's.
	for _, st := range steps {
		if strings.Contains(st.Script, "vgremove") && !strings.Contains(st.Script, "vg="+cloudhypervisor.VG+"\n") {
			t.Errorf("step %q removes a volume group other than %s", st.Name, cloudhypervisor.VG)
		}
	}
}

func TestPlanNeverStopsSSH(t *testing.T) {
	for _, s := range Plan(PlanInput{Purge: []string{"docker.io"}, Tables: []string{"inet kevaso"}, IPForward: "1"}) {
		for _, bad := range []string{"ssh", "reboot", "poweroff", "iptables -F", "nft flush ruleset"} {
			if strings.Contains(s.Script, bad) {
				t.Errorf("step %q contains %q", s.Name, bad)
			}
		}
	}
}

func TestChecklistCoversThePlan(t *testing.T) {
	checks := Checklist(Ports)
	all := ""
	for _, c := range checks {
		all += c.Script + "\n"
		if c.Name == "" || c.Script == "" {
			t.Errorf("an empty check: %+v", c)
		}
	}
	for _, p := range Paths {
		if !strings.Contains(all, p) {
			t.Errorf("no check looks for %s", p)
		}
	}
	for _, p := range Processes {
		if !strings.Contains(all, p) {
			t.Errorf("no check looks for the process %s", p)
		}
	}
	for _, want := range []string{"6443", "443", "18080", "vgs", "losetup", "dmsetup", HostsMarker, "kevaso-", "kvbr", "/proc/mounts", "nft list tables"} {
		if !strings.Contains(all, want) {
			t.Errorf("no check mentions %q", want)
		}
	}
}

func TestReport(t *testing.T) {
	checks := []Check{{"a", "x"}, {"b", "y"}}
	if err := Report(checks, map[string]string{"a": "\n", "b": ""}, nil); err != nil {
		t.Fatalf("clean: %v", err)
	}
	err := Report(checks, map[string]string{"a": "kvbr0\nkvt123\n", "b": ""}, []string{"package still installed: docker.io"})
	if !errors.Is(err, ErrNotClean) {
		t.Fatalf("got %v", err)
	}
	for _, want := range []string{"a: kvbr0, kvt123", "package still installed: docker.io"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("report lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "b:") {
		t.Errorf("a clean check reported: %v", err)
	}
}
