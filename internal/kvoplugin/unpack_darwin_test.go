package kvoplugin

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// An app bundle's code signature still holds once kvo has unpacked it (macOS kills a program whose
// signature broke, and notifications and the keychain go by the signed bundle).
func TestUnpackKeepsAnAppsSignature(t *testing.T) {
	for _, tool := range []string{"codesign", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("needs " + tool)
		}
	}
	src := t.TempDir()
	app := filepath.Join(src, "T.app", "Contents")
	if err := os.MkdirAll(filepath.Join(app, "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	exe, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Skip(err)
	}
	_ = os.WriteFile(filepath.Join(app, "MacOS", "T"), exe, 0o755)
	_ = os.WriteFile(filepath.Join(app, "Info.plist"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.kevaso.test</string><key>CFBundleExecutable</key><string>T</string></dict></plist>`), 0o644)
	run := func(dir string, name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "COPYFILE_DISABLE=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run(src, "codesign", "--force", "--sign", "-", "T.app")
	run(src, "tar", "--no-xattrs", "-czf", "a.tar.gz", "T.app")
	b, err := os.ReadFile(filepath.Join(src, "a.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "files")
	_ = os.Mkdir(root, 0o755)
	if err := UnpackTarGz(bytes.NewReader(b), root); err != nil {
		t.Fatal(err)
	}
	run(root, "codesign", "--verify", "--strict", "T.app")
}
