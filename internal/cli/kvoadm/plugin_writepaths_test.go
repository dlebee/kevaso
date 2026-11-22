package kvoadm

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kplugin"
)

func mustUnit(t *testing.T, o PluginOptions) string {
	t.Helper()
	u, err := PluginUnit(o)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// K-039: a side that asks only for a folder to write used to install with nothing asked ("writes
// only …", no --yes): it is granted only with --yes, or "y" in a terminal.
func TestWritePathsNeedTheOperatorsYes(t *testing.T) {
	o := PluginOptions{Name: "x", Needs: kplugin.Needs{WritePaths: []string{"/var/lib/kevaso-plugin-x"}}}
	var out bytes.Buffer
	if err := grantNeeds(o, bufio.NewReader(strings.NewReader("y\n")), strings.NewReader("y\n"), &out); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("a write path without --yes (stdin not a terminal): %v", err)
	}
	if !strings.Contains(out.String(), "writes /var/lib/kevaso-plugin-x") {
		t.Errorf("the folder isn't shown:\n%s", out.String())
	}
	defer func(f func(io.Reader) bool) { isTerminal = f }(isTerminal)
	isTerminal = func(io.Reader) bool { return true }
	for answer, granted := range map[string]bool{"y\n": true, "yes\n": true, "\n": false, "n\n": false, "": false} {
		out.Reset()
		err := grantNeeds(o, bufio.NewReader(strings.NewReader(answer)), nil, &out)
		if (err == nil) != granted {
			t.Errorf("answer %q: %v", answer, err)
		}
		if !strings.Contains(out.String(), "[y/N]") {
			t.Errorf("not asked:\n%s", out.String())
		}
	}
	o.Yes = true
	if err := grantNeeds(o, nil, nil, &out); err != nil {
		t.Fatal(err)
	}
}

// The unit is where the folder is granted: needs that didn't come through ParseManifest (or a
// manifest checked by an older kvoadm) are refused there too, whatever --yes says.
func TestUnitRefusesForeignWritePaths(t *testing.T) {
	for _, p := range []string{"/var/lib/kevaso", "/etc", "/var/lib", "/var/lib/kevaso-plugin-y", "/var/lib/kevaso-plugin-x/sub", "/x\nExecStartPre=/bin/sh"} {
		o := PluginOptions{Name: "x", Yes: true, Needs: kplugin.Needs{WritePaths: []string{p}}}
		if u, err := PluginUnit(o); err == nil {
			t.Errorf("%q: unit rendered:\n%s", p, u)
		}
		if err := grantNeeds(o, nil, nil, io.Discard); err == nil {
			t.Errorf("%q: granted", p)
		}
	}
}

// On the host: a write path with a symlink in it is refused (systemd would grant what it points
// at), an existing folder's mode is left alone (install -d -m 0700 on /etc broke every service),
// a missing one is made 0700; systemd's own private/ link for a dynamic user's state is allowed.
func TestWritePathScriptOnTheHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script runs on the Linux host; Windows has no Unix modes to check")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run := func(p string) error {
		return exec.Command("sh", "-c", WritePathScript(p)).Run()
	}
	existing := filepath.Join(root, "existing")
	_ = os.Mkdir(existing, 0o755)
	if err := run(existing); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(existing); fi.Mode().Perm() != 0o755 {
		t.Errorf("an existing folder's mode changed to %v", fi.Mode().Perm())
	}
	missing := filepath.Join(root, "missing")
	if err := run(missing); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(missing); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("a missing folder: %v %v", fi, err)
	}
	target := filepath.Join(root, "etc")
	_ = os.Mkdir(target, 0o755)
	link := filepath.Join(root, "link")
	_ = os.Symlink(target, link)
	if err := run(link); err == nil {
		t.Error("a symlink was granted")
	}
	if err := run(filepath.Join(link, "deeper")); err == nil {
		t.Error("a folder under a symlink was granted")
	}
	if _, err := os.Stat(filepath.Join(target, "deeper")); err == nil {
		t.Error("a folder was made through the symlink")
	}
	file := filepath.Join(root, "file")
	_ = os.WriteFile(file, nil, 0o600)
	if err := run(file); err == nil {
		t.Error("a file was granted")
	}
	if s := WritePathScript("/var/lib/kevaso-plugin-x"); !strings.Contains(s, "'private/kevaso-plugin-x'") {
		t.Errorf("systemd's private link isn't allowed: %s", s)
	}
}
