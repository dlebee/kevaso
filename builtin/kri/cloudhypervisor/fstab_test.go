package cloudhypervisor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// An empty fstab is what a crash during the old truncate-and-write left behind. The script
// remounts / read-write, rebuilds the guest's own root line from the live mount, and replaces
// fstab by renaming a synced file in the same directory. A second run with the same volumes
// does not write again.
func TestGuestFstabSurvivesACrashAndASecondBoot(t *testing.T) {
	root := t.TempDir()
	etcdir := filepath.Join(root, "etc")
	if err := os.Mkdir(etcdir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The file the crash left: zero bytes. The guest's own lines (root and the EFI partition)
	// are gone with it.
	if err := os.WriteFile(filepath.Join(etcdir, "fstab"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "log")
	writeStub(t, bin, "findmnt", `#!/bin/sh
case "$3" in
  OPTIONS) printf '%s\n' "${FAKE_FIND_OPTS:-rw,relatime}" ;;
  SOURCE) printf '%s\n' "${FAKE_FIND_SRC:-/dev/vda1}" ;;
  FSTYPE) printf '%s\n' "${FAKE_FIND_TYPE:-ext4}" ;;
esac
`)
	writeStub(t, bin, "blkid", `#!/bin/sh
case "$2" in
  LABEL) printf '%s\n' "${FAKE_LABEL-cloudimg-rootfs}" ;;
  UUID) printf '%s\n' "${FAKE_UUID:-11111111-2222-3333-4444-555555555555}" ;;
esac
`)
	writeStub(t, bin, "mount", "#!/bin/sh\nprintf 'mount %s\\n' \"$*\" >> \"$FAKE_LOG\"\n")
	writeStub(t, bin, "mountpoint", "#!/bin/sh\nexit 1\n")
	writeStub(t, bin, "systemctl", "#!/bin/sh\nexit 0\n")
	writeStub(t, bin, "sync", "#!/bin/sh\nprintf 'sync %s\\n' \"$*\" >> \"$FAKE_LOG\"\n")

	mnt := filepath.Join(root, "mnt")
	sc := GuestMountScript(Layout{Shares: []Share{{Tag: "kvdata", MountPath: mnt}}})
	env := []string{
		"PATH=" + bin + ":" + os.Getenv("PATH"),
		"KEVASO_GUEST_ETC=" + etcdir,
		"FAKE_LOG=" + log,
		"FAKE_FIND_OPTS=ro,relatime",
		"FAKE_LABEL=cloudimg-rootfs",
	}
	run := func() {
		t.Helper()
		cmd := exec.Command("sh", "-c", sc)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("script: %v\n%s", err, out)
		}
	}
	run()
	got, err := os.ReadFile(filepath.Join(etcdir, "fstab"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{
		"LABEL=cloudimg-rootfs / ext4 discard,commit=30,errors=remount-ro 0 1\n",
		"kvdata " + mnt + " virtiofs nofail 0 0\n",
		fstabBegin, fstabEnd,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("fstab lacks %q:\n%s", want, text)
		}
	}
	if strings.Count(text, " / ") != 1 {
		t.Errorf("root line once, got:\n%s", text)
	}
	trace, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(trace), "mount -o remount,rw /") {
		t.Errorf("did not remount / read-write:\n%s", trace)
	}
	if !strings.Contains(string(trace), "sync -f "+etcdir) {
		t.Errorf("did not sync the directory:\n%s", trace)
	}
	syncedFile := false
	for _, line := range strings.Split(string(trace), "\n") {
		if strings.HasPrefix(line, "sync ") && !strings.HasPrefix(line, "sync -f ") && strings.Contains(line, etcdir+"/") {
			syncedFile = true
		}
	}
	if !syncedFile {
		t.Errorf("did not sync the new fstab before renaming it:\n%s", trace)
	}
	left, _ := filepath.Glob(filepath.Join(etcdir, "fstab.*"))
	if len(left) != 0 {
		t.Errorf("temp fstab left behind: %v", left)
	}

	// The guest's own lines stay, and an unchanged block is not written again.
	kept := "LABEL=cloudimg-rootfs / ext4 discard,commit=30,errors=remount-ro 0 1\nLABEL=UEFI /boot/efi vfat umask=0077 0 1\n" +
		fstabBegin + "\nold line\n" + fstabEnd + "\n"
	if err := os.WriteFile(filepath.Join(etcdir, "fstab"), []byte(kept), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	env[3] = "FAKE_FIND_OPTS=rw,relatime"
	run()
	text = string(mustRead(t, filepath.Join(etcdir, "fstab")))
	if !strings.Contains(text, "LABEL=UEFI /boot/efi vfat umask=0077 0 1\n") || strings.Contains(text, "old line") {
		t.Fatalf("guest lines:\n%s", text)
	}
	if strings.Count(text, fstabBegin) != 1 {
		t.Fatalf("block:\n%s", text)
	}
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	run()
	if again := string(mustRead(t, filepath.Join(etcdir, "fstab"))); again != text {
		t.Fatalf("second run changed fstab:\n%s", again)
	}
	if trace := string(mustRead(t, log)); strings.Contains(trace, "sync ") {
		t.Fatalf("unchanged fstab was written again:\n%s", trace)
	}
}

func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
