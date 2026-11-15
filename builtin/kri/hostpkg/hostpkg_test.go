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
