package hostreset

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// inspectOut is what InspectScript prints: record (nested sections as "=== "), installed, silos,
// the volume group, the state now.
func inspectOut(record *Record, installed bool, silos, pvs, lvs []string, now State) string {
	var b strings.Builder
	b.WriteString("== record\n")
	if record != nil {
		b.WriteString(strings.ReplaceAll(record.Render(), "== ", "=== "))
	}
	b.WriteString("== installed\n")
	if installed {
		b.WriteString("kevasod=yes\nrunning=yes\n")
	} else {
		b.WriteString("kevasod=no\nrunning=no\n")
	}
	b.WriteString("== silos\n" + strings.Join(silos, "\n") + "\n== pvs\n" + strings.Join(pvs, "\n") + "\n== lvs\n" + strings.Join(lvs, "\n") + "\n")
	b.WriteString("== state\n" + strings.ReplaceAll(now.Render(), "== ", "=== "))
	return b.String()
}

var afterInstall = State{
	Packages:  append(slices.Clone(fresh.Packages), "docker.io", "containerd", "qemu-utils", "virtiofsd"),
	Tables:    []string{"bridge kevaso", "inet kevaso", "inet provider"},
	IPForward: "1",
}

func TestParseInspection(t *testing.T) {
	rec := Record{State: fresh, DockerJSONBefore: true}
	in, err := ParseInspection(inspectOut(&rec, true, []string{"vm kevaso-silo-0123456789.service", "container web/api"},
		[]string{"/dev/loop3 " + StorageImage}, []string{"kv-0123456789 5.00g", "kv-0123456789-ab12cd34 1.00g"}, afterInstall))
	if err != nil {
		t.Fatal(err)
	}
	if in.Record == nil || !in.Record.DockerJSONBefore || !slices.Equal(in.Record.Packages, fresh.Packages) {
		t.Errorf("record %+v", in.Record)
	}
	if !in.Installed || !in.Running || len(in.Silos) != 2 || len(in.Volumes) != 2 || !in.OnLoopFile() {
		t.Errorf("inspection %+v", in)
	}
	if !slices.Equal(in.Now.Tables, afterInstall.Tables) {
		t.Errorf("state now %+v", in.Now)
	}
	none, err := ParseInspection(inspectOut(nil, false, nil, nil, nil, fresh))
	if err != nil || none.Record != nil || none.Installed || len(none.PVs) != 0 || none.OnLoopFile() {
		t.Fatalf("a bare host: %+v %v", none, err)
	}
	if _, err := ParseInspection("== installed\nkevasod=no\n"); err == nil {
		t.Error("an inspection without its sections was accepted")
	}
	if _, err := ParseInspection(inspectOut(nil, false, nil, []string{"/dev/sdb"}, nil, fresh)); err == nil {
		t.Error("a malformed physical volume line was accepted")
	}
}

func TestDecideRefusesAHostWithSilos(t *testing.T) {
	in := Inspection{Installed: true, Silos: []string{"vm kevaso-silo-0123456789.service", "container web/api"}, Now: afterInstall}
	_, err := Decide(in, Flags{})
	if !errors.Is(err, ErrSilos) || !strings.Contains(err.Error(), "container web/api") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("got %v", err)
	}
	d, err := Decide(in, Flags{Force: true})
	if err != nil || !strings.Contains(strings.Join(d.Summary, "\n"), "destroy the silos still here (--force): vm kevaso-silo") {
		t.Fatalf("forced: %v %v", d.Summary, err)
	}
}

func TestDecideFromARecord(t *testing.T) {
	rec := Record{State: fresh}
	d, err := Decide(Inspection{Record: &rec, Installed: true, PVs: []PV{{"/dev/loop3", StorageImage}}, Volumes: []string{"kv-01-ab 1.00g"}, Now: afterInstall}, Flags{})
	if err != nil {
		t.Fatal(err)
	}
	p := d.Plan
	if !slices.Equal(p.Purge, []string{"containerd", "docker.io", "qemu-utils", "virtiofsd"}) || !slices.Equal(p.Tables, []string{"bridge kevaso", "inet kevaso"}) ||
		p.IPForward != "0" || !p.DockerOurs || p.Storage != StorageLoop || !d.Checks.DockerGone || d.Checks.KeepVG {
		t.Fatalf("plan %+v checks %+v", p, d.Checks)
	}
	if !slices.Equal(d.Lost, []string{"kv-01-ab 1.00g"}) {
		t.Errorf("lost %v", d.Lost)
	}
	sum := strings.Join(d.Summary, "\n")
	for _, want := range []string{"from the install record", "Docker was installed by Kevaso", "loop file", "kvoadm host remove"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %q:\n%s", want, sum)
		}
	}
	if strings.Contains(sum, "inet provider") {
		t.Error("a table of the record is to be deleted")
	}

	// Docker was there before: it stays, its daemon.json comes back.
	before := Record{State: State{Packages: append(slices.Clone(fresh.Packages), "docker.io", "containerd"), Tables: fresh.Tables, IPForward: "1"}, DockerJSONBefore: true}
	d, err = Decide(Inspection{Record: &before, Installed: true, Now: afterInstall}, Flags{})
	if err != nil || d.Plan.DockerOurs || d.Plan.DockerJSON != DockerJSONRestore || d.Checks.DockerGone || slices.Contains(d.Plan.Purge, "docker.io") || d.Plan.IPForward != "1" {
		t.Fatalf("docker before: %+v %v", d.Plan, err)
	}
}

func TestDecidePodmanOurs(t *testing.T) {
	rec := Record{State: fresh}
	now := afterInstall
	now.Packages = append(slices.Clone(now.Packages), "podman", "catatonit")
	d, err := Decide(Inspection{Record: &rec, Now: now}, Flags{})
	if err != nil || !d.Plan.PodmanOurs || !d.Checks.PodmanGone || !slices.Contains(d.Plan.Purge, "podman") || !slices.Contains(d.Plan.Purge, "catatonit") {
		t.Fatalf("podman installed by Kevaso: %+v %+v %v", d.Plan, d.Checks, err)
	}
	if d, _ := Decide(Inspection{Record: &Record{State: now}, Now: now}, Flags{}); d.Plan.PodmanOurs {
		t.Error("a podman that was there before is treated as Kevaso's")
	}
}

func TestDecideRemovesTheDaemonJSONKevasoMade(t *testing.T) {
	before := Record{State: State{Packages: append(slices.Clone(fresh.Packages), "docker.io"), Tables: fresh.Tables, IPForward: "0"}}
	d, err := Decide(Inspection{Record: &before, Now: afterInstall}, Flags{})
	if err != nil || d.Plan.DockerOurs || d.Plan.DockerJSON != DockerJSONRemove {
		t.Fatalf("docker before, no daemon.json before: %+v %v", d.Plan, err)
	}
	if d, _ := Decide(Inspection{Now: afterInstall}, Flags{}); d.Plan.DockerJSON != DockerJSONIfKevasos {
		t.Errorf("no record: %+v", d.Plan)
	}
}

func TestDecideWithoutARecordUsesTheFixedLists(t *testing.T) {
	d, err := Decide(Inspection{Installed: true, Now: afterInstall}, Flags{})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Plan.Purge) != 0 || d.Plan.IPForward != "" || d.Plan.DockerOurs || !slices.Equal(d.Plan.Tables, []string{"bridge kevaso", "inet kevaso"}) {
		t.Fatalf("plan %+v", d.Plan)
	}
	sum := strings.Join(d.Summary, "\n")
	if !strings.Contains(sum, "NO INSTALL RECORD") || !strings.Contains(sum, "left installed") || !strings.Contains(sum, "docker.io") {
		t.Errorf("summary:\n%s", sum)
	}
}

func TestDecideNeverWipesARealDiskUnasked(t *testing.T) {
	rec := Record{State: fresh}
	disk := Inspection{Record: &rec, PVs: []PV{{"/dev/nvme1n1", "disk"}}, Volumes: []string{"kv-01 20.00g", "kv-01-ab 100.00g"}, Now: afterInstall}
	d, err := Decide(disk, Flags{Force: true})
	if err != nil || d.Plan.Storage != StorageKeep || !d.Checks.KeepVG || len(d.Lost) != 0 {
		t.Fatalf("a disk volume group without --wipe-storage: %+v lost %v %v", d.Plan, d.Lost, err)
	}
	if sum := strings.Join(d.Summary, "\n"); !strings.Contains(sum, "KEEP the volume group") || !strings.Contains(sum, "/dev/nvme1n1") || !strings.Contains(sum, "kv-01-ab 100.00g") {
		t.Errorf("summary:\n%s", sum)
	}
	d, err = Decide(disk, Flags{WipeStorage: true})
	if err != nil || d.Plan.Storage != StorageWipe || d.Checks.KeepVG || !slices.Equal(d.Lost, disk.Volumes) {
		t.Fatalf("--wipe-storage: %+v lost %v %v", d.Plan, d.Lost, err)
	}
	if !strings.Contains(strings.Join(d.Summary, "\n"), "WIPE the volume group") {
		t.Errorf("summary: %v", d.Summary)
	}
	// A volume group that was there before Kevaso is kept even on the loop file's path.
	pre := Record{State: fresh, VGBefore: true}
	d, _ = Decide(Inspection{Record: &pre, PVs: []PV{{"/dev/loop0", StorageImage}}, Now: afterInstall}, Flags{})
	if d.Plan.Storage != StorageKeep || !strings.Contains(strings.Join(d.Summary, "\n"), "it was there before Kevaso") {
		t.Errorf("a volume group from before: %+v %v", d.Plan, d.Summary)
	}
	// A loop device on some other file isn't Kevaso's either.
	d, _ = Decide(Inspection{Record: &rec, PVs: []PV{{"/dev/loop0", "/srv/other.img"}}, Now: afterInstall}, Flags{})
	if d.Plan.Storage != StorageKeep {
		t.Errorf("a loop device on another file: %+v", d.Plan)
	}
}

func TestInspectScriptPrintsEverySection(t *testing.T) {
	for _, sec := range []string{"record", "installed", "silos", "pvs", "lvs", "state"} {
		if !strings.Contains(InspectScript, "echo '== "+sec+"'") {
			t.Errorf("InspectScript prints no %q section", sec)
		}
	}
	for _, nested := range []string{"=== packages", "=== tables", "=== ipforward", "sed 's/^== /=== /'"} {
		if !strings.Contains(InspectScript, nested) {
			t.Errorf("InspectScript doesn't nest %q", nested)
		}
	}
	if strings.Contains(InspectScript, "echo '== packages'") {
		t.Error("the state's sections aren't nested")
	}
}
