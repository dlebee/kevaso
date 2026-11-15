package hostreset

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// These tests run the reset's steps for real, in sh, with every program a step can use replaced
// by a stub that records its arguments (T-08): what a destructive command is aimed at is read off
// what it was run with, not off the script's text. A program that is not stubbed does not exist
// in the steps' PATH, so a step can neither delete anything of the machine the test runs on nor
// reach for something the stubs do not know.

// stubbed is every program the plan's scripts call that changes the machine.
var stubbed = []string{"rm", "docker", "podman", "systemctl", "pkill", "ip", "nft", "sysctl", "vgs", "pvs", "lvremove", "vgremove",
	"pvremove", "losetup", "apt-get", "cp", "sed", "userdel", "groupdel", "umount", "sleep", "cmp", "mv"}

// harmless programs the steps use to read, found on the machine the test runs on.
var harmless = []string{"awk", "grep", "tr", "cut", "sort", "basename", "cat", "head", "printf", "echo", "test", "["}

// canned answers: what the stubs say when asked (what a host with Kevaso's and someone else's things on it would).
const stubScript = `#!/bin/sh
name="${0##*/}"
printf '%s' "$name" >> "$STUBLOG"
for a in "$@"; do printf ' %s' "$a" >> "$STUBLOG"; done
printf '\n' >> "$STUBLOG"
case "$name $*" in
  "docker ps -aq --filter"*)          echo kevaso-c1 ;;
  "docker ps -aq")                    echo other-c1 other-c2 ;;
  "docker ps -a --format"*)           printf 'osc1 openshell-kv-0123456789\nother1 other-kv-x\nother2 nginx\n' ;;
  "docker volume ls -q --filter"*)    echo kevaso-v1 ;;
  "docker volume ls -q")              echo other-v1 ;;
  "podman ps -aq --filter"*)          echo kevaso-pc1 ;;
  "podman ps -aq")                    echo other-pc1 ;;
  "podman volume ls -q --filter"*)    echo kevaso-pv1 ;;
  "podman volume ls -q")              echo other-pv1 ;;
  "pvs "*)                            echo "$STUB_PV" ;;
  "losetup -n -O BACK-FILE"*)         echo "$STUB_BACKFILE" ;;
  "losetup -n -O NAME"*)              : ;;
  "systemctl list-units"*)            : ;;
  "vgs "*)                            exit "${STUB_VG_EXIT:-0}" ;;
esac
exit 0
`

type ran struct{ lines []string }

func (r ran) calls(cmd string) [][]string {
	var out [][]string
	for _, l := range r.lines {
		f := strings.Fields(l)
		if len(f) > 0 && f[0] == cmd {
			out = append(out, f[1:])
		}
	}
	return out
}

func (r ran) text() string { return strings.Join(r.lines, "\n") }

// runStep runs the step called name (a prefix of its name) from the plan, returns what the stubs
// saw and the step's exit error.
func runStep(t *testing.T, in PlanInput, name string, env ...string) (ran, error) {
	t.Helper()
	var step *Step
	for _, s := range Plan(in) {
		if strings.HasPrefix(s.Name, name) {
			s := s
			step = &s
			break
		}
	}
	if step == nil {
		t.Fatalf("no step %q in the plan", name)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range stubbed {
		if err := os.WriteFile(filepath.Join(bin, p), []byte(stubScript), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range harmless {
		if path, err := exec.LookPath(p); err == nil && !slices.Contains(stubbed, p) {
			_ = os.Symlink(path, filepath.Join(bin, p))
		}
	}
	log := filepath.Join(dir, "log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", step.Script)
	cmd.Env = append([]string{"PATH=" + bin, "STUBLOG=" + log, "HOME=" + dir}, env...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	b, _ := os.ReadFile(log)
	t.Logf("step %q: %v\n%s", step.Name, err, out)
	return ran{lines: strings.Split(strings.TrimSpace(string(b)), "\n")}, err
}

// Every step of every plan is a script sh accepts, whatever is in the input.
func TestEveryStepOfEveryPlanIsValidShell(t *testing.T) {
	inputs := []PlanInput{{}, full, {Storage: StorageLoop}, {Storage: StorageWipe}, {DockerOurs: true, PodmanOurs: true, DockerJSON: DockerJSONRestore},
		{DockerJSON: DockerJSONRemove, Purge: []string{"docker.io"}, Tables: []string{"inet kevaso"}, IPForward: "1"}}
	for i, in := range inputs {
		for _, s := range Plan(in) {
			if out, err := exec.Command("/bin/sh", "-n", "-c", s.Script).CombinedOutput(); err != nil {
				t.Errorf("input %d, step %q is not valid shell: %v\n%s", i, s.Name, err, out)
			}
		}
	}
}

// With Docker not Kevaso's, only Kevaso's containers and volumes (by label) are removed: the
// other things the host's Docker has are never named to a remove.
func TestADockerThatIsNotKevasosLosesOnlyKevasosContainersAndVolumes(t *testing.T) {
	r, _ := runStep(t, PlanInput{DockerOurs: false}, "remove Kevaso's containers and volumes")
	rm := r.calls("docker")
	var removed []string
	for _, c := range rm {
		if len(c) > 0 && (c[0] == "rm" || (len(c) > 1 && c[0] == "volume" && c[1] == "rm")) {
			removed = append(removed, strings.Join(c, " "))
		}
	}
	if len(removed) != 2 {
		t.Fatalf("removes %v, want Kevaso's container and volume", removed)
	}
	if strings.Contains(strings.Join(removed, " "), "other-") || !strings.Contains(removed[0], "kevaso-c1") || !strings.Contains(removed[1], "kevaso-v1") {
		t.Fatalf("removed %v: something that is not Kevaso's", removed)
	}
	for _, c := range r.calls("docker") {
		if strings.Join(c, " ") == "system prune -af" || (len(c) > 0 && c[0] == "system") {
			t.Fatalf("a Docker that is not Kevaso's was pruned: %v", c)
		}
	}
}

func TestADockerThatIsKevasosLosesEveryContainerAndVolume(t *testing.T) {
	r, _ := runStep(t, PlanInput{DockerOurs: true}, "remove containers, volumes and images")
	if !strings.Contains(r.text(), "docker rm -f other-c1 other-c2") || !strings.Contains(r.text(), "docker volume rm -f other-v1") {
		t.Fatalf("Kevaso's own Docker was not emptied (the control for the test above): %s", r.text())
	}
}

func TestAPodmanThatIsNotKevasosLosesOnlyKevasosContainersAndVolumes(t *testing.T) {
	r, _ := runStep(t, PlanInput{PodmanOurs: false}, "remove Kevaso's podman containers")
	if strings.Contains(r.text(), "other-") || strings.Contains(r.text(), "podman rm -af") || strings.Contains(r.text(), "system reset") {
		t.Fatalf("a podman that is not Kevaso's lost things that are not Kevaso's: %s", r.text())
	}
	if !strings.Contains(r.text(), "podman rm -f -t 0 kevaso-pc1") {
		t.Fatalf("Kevaso's own container was not removed: %s", r.text())
	}
}

func TestAPodmanThatIsKevasosIsEmptiedAll(t *testing.T) {
	r, _ := runStep(t, PlanInput{PodmanOurs: true}, "remove podman's containers")
	if !strings.Contains(r.text(), "podman rm -af") {
		t.Fatalf("Kevaso's own podman was not emptied (the control for the test above): %s", r.text())
	}
}

// The files step removes Kevaso's paths and nothing else, and never into another file system.
func TestTheFilesStepRemovesOnlyKevasosPathsAndNeverCrossesAFileSystem(t *testing.T) {
	for _, in := range []PlanInput{{}, {DockerOurs: true, PodmanOurs: true}} {
		r, err := runStep(t, in, "remove Kevaso's files")
		if err != nil {
			t.Fatal(err)
		}
		rms := r.calls("rm")
		if len(rms) != 1 {
			t.Fatalf("the files step ran rm %d times: %v", len(rms), rms)
		}
		args := rms[0]
		if !slices.Contains(args, "-rf") || !slices.Contains(args, "--one-file-system") {
			t.Fatalf("rm %v: it can cross into another file system", args)
		}
		n := 0
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			n++
			if !underAllowed(a) {
				t.Errorf("rm %s: outside Kevaso's paths", a)
			}
		}
		if want := len(Paths); in.DockerOurs && n <= want {
			t.Errorf("Docker is Kevaso's but only %d paths removed", n)
		}
		if !in.DockerOurs && slices.Contains(args, "/var/lib/docker") {
			t.Errorf("Docker is not Kevaso's and rm names /var/lib/docker")
		}
		if !in.PodmanOurs && slices.Contains(args, "/var/lib/containers") {
			t.Errorf("podman is not Kevaso's and rm names /var/lib/containers")
		}
	}
}

// The volume group is removed on its loop file alone, never on a real disk, unless wiping was asked.
func TestTheLoopVolumeGroupIsRemovedOnlyOnItsOwnFile(t *testing.T) {
	cases := []struct {
		name     string
		pv, back string
		removed  bool
	}{
		{"on Kevaso's loop file", "/dev/loop7", StorageImage, true},
		{"on another loop file", "/dev/loop7", "/home/someone/disk.img", false},
		{"on a real disk", "/dev/nvme0n1p3", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := runStep(t, PlanInput{Storage: StorageLoop}, "remove volume group", "STUB_PV="+tc.pv, "STUB_BACKFILE="+tc.back)
			gone := len(r.calls("lvremove")) > 0 || len(r.calls("vgremove")) > 0 || len(r.calls("pvremove")) > 0
			if gone != tc.removed {
				t.Fatalf("volume group removed = %v, want %v (step error %v)", gone, tc.removed, err)
			}
			if !tc.removed && err == nil {
				t.Fatal("the step refused but exited 0: the reset would report success")
			}
		})
	}
}

func TestOnlyAskingToWipeRemovesAVolumeGroupOnARealDisk(t *testing.T) {
	r, err := runStep(t, PlanInput{Storage: StorageWipe}, "wipe volume group", "STUB_PV=/dev/nvme0n1p3")
	if err != nil || len(r.calls("vgremove")) != 1 {
		t.Fatalf("--wipe-storage did not wipe: %v %v", err, r.lines)
	}
}

func TestKeepingStorageNeverTouchesTheVolumeGroup(t *testing.T) {
	for _, s := range Plan(PlanInput{Storage: StorageKeep}) {
		if strings.Contains(s.Script, "lvremove") || strings.Contains(s.Script, "vgremove") {
			t.Errorf("step %q removes volumes although storage is kept", s.Name)
		}
	}
}

// Only words that are safe reach a package or table command.
func TestOnlySafeWordsReachAPurgeOrATableCommand(t *testing.T) {
	r, _ := runStep(t, PlanInput{Purge: []string{"docker.io", "bad;reboot", "$(reboot)"}}, "purge")
	if got := r.calls("apt-get"); len(got) == 0 || strings.Contains(r.text(), "reboot") {
		t.Fatalf("purge ran %v", r.lines)
	}
	r, _ = runStep(t, PlanInput{Tables: []string{"inet kevaso", "inet x;reboot", "bridge kevaso"}}, "delete nftables tables")
	nft := r.calls("nft")
	if len(nft) != 2 || strings.Contains(r.text(), "reboot") {
		t.Fatalf("nft ran %v", nft)
	}
}
