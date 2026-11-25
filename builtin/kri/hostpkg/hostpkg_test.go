package hostpkg

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// K-113: what an install adds (its dependencies too) is appended to the record of what Kevaso
// installed; what was there before is not, and the install's exit status is kept.
func TestRecordingNamesOnlyWhatTheInstallAdded(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "db")
	if err := os.WriteFile(db, []byte("ii curl\nii docker.io\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	// dpkg-query prints the fake database; apt-get adds its arguments and a dependency, then
	// exits as $FAIL says.
	for name, body := range map[string]string{
		"dpkg-query": "#!/bin/sh\nawk '{print $1, $2}' " + db + "\n",
		"apt-get":    "#!/bin/sh\nfor p in \"$@\"; do case \"$p\" in -*|install) ;; *) echo \"ii $p\" >> " + db + ";; esac; done\necho 'ii runc' >> " + db + "\nexit ${FAIL:-0}\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(dir, "rec", "installed")
	run := func(fail string, pkgs ...string) error {
		cmd := exec.Command("sh", append([]string{"-c", recording(`apt-get install -y "$@"`, file), "sh"}, pkgs...)...)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "FAIL="+fail)
		return cmd.Run()
	}
	if err := run("0", "podman", "docker.io"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	if got := strings.Fields(string(b)); strings.Join(got, " ") != "podman runc" {
		t.Fatalf("recorded %q: want what the install added (podman and its dependency runc), not docker.io, which was there", got)
	}
	if err := run("100", "qemu-utils"); err == nil {
		t.Fatal("a failed install's exit status was lost")
	}
	b, _ = os.ReadFile(file)
	if got := strings.Fields(string(b)); strings.Join(got, " ") != "podman runc qemu-utils" {
		t.Fatalf("recorded %q after a failed install that added qemu-utils", got)
	}
}

// A kevasod restart can cut the script off after apt-get installed and before the record is
// written (found on a real machine: docker.io never recorded, and a reset left it). The snapshot
// of before stays, and the next run of the same install counts from it.
func TestRecordingSurvivesARunCutOffAfterTheInstall(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "db")
	if err := os.WriteFile(db, []byte("ii curl\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	// apt-get installs its arguments; with $CUT set, the run is killed right after (kill -9 of
	// its own shell, as systemd stopping kevasod does), before the record is written.
	for name, body := range map[string]string{
		"dpkg-query": "#!/bin/sh\nawk '{print $1, $2}' " + db + "\n",
		"apt-get":    "#!/bin/sh\nfor p in \"$@\"; do case \"$p\" in -*|install) ;; *) grep -q \" $p$\" " + db + " || echo \"ii $p\" >> " + db + ";; esac; done\n[ -n \"$CUT\" ] && kill -9 $PPID\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(dir, "rec", "installed")
	run := func(cut string, pkgs ...string) error {
		cmd := exec.Command("sh", append([]string{"-c", recording(`apt-get install -y "$@"`, file), "sh"}, pkgs...)...)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "CUT="+cut)
		return cmd.Run()
	}
	_ = run("yes", "docker.io") // killed after the install
	if b, _ := os.ReadFile(file); strings.Contains(string(b), "docker.io") {
		t.Fatal("the cut-off run wrote its record after all: the test doesn't cut it")
	}
	if err := run("", "docker.io"); err != nil { // kevasod started again: the same install
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	if got := strings.Fields(string(b)); strings.Join(got, " ") != "docker.io" {
		t.Fatalf("recorded %q: docker.io, installed by the cut-off run, is Kevaso's", got)
	}
	if left, _ := filepath.Glob(file + ".before-*"); len(left) != 0 {
		t.Fatalf("snapshot left after a full run: %v", left)
	}
}
