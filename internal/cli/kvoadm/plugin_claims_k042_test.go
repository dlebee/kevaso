package kvoadm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// K-042, at install: kevasod refuses a plugin that claims a class or DNS name another plugin
// serves (internal/plugins), and kvoadm plugin install now waits for kevasod's word on the plugin
// it just started: a refusal is the install's error, naming both plugins, and the refused unit is
// stopped. The script runs on the host; here against a fake journalctl.
func TestPluginInstallReportsKevasodsRefusal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script runs on the Linux host, with a fake journalctl on a Unix PATH")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	bin := t.TempDir()
	journal := filepath.Join(t.TempDir(), "journal")
	fake := "#!/bin/sh\ncat " + journal + "\n"
	if err := os.WriteFile(filepath.Join(bin, "journalctl"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(lines string) string {
		t.Helper()
		if err := os.WriteFile(journal, []byte(lines), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", "-c", RegistrationScript("aaa", "1700000000", 2))
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("script: %v: %s", err, out)
		}
		return string(out)
	}
	refusedLine := "2026/11/15 10:00:00 plugin aaa 1.0.0 at /run/kevaso-plugins/aaa/plugin.sock refused: storage class acme-block: plugin acme serves it already (at /run/kevaso-plugins/acme/plugin.sock): remove one of the two plugins\n"
	for _, tc := range []struct {
		journal    string
		registered bool
		says       string
	}{
		{"2026/11/15 10:00:00 plugin acme 1.0.0 registered (storage acme-block)\n" + refusedLine, false, "storage class acme-block: plugin acme serves it already"},
		{"2026/11/15 10:00:00 plugin aaa 1.0.0 registered (storage aaa-block)\n", true, "plugin aaa 1.0.0 registered"},
		{"2026/11/15 10:00:00 plugin aaa answering again (after 2s)\n", true, "answering again"},
		// another plugin's refusal that names aaa is not aaa's
		{"2026/11/15 10:00:00 plugin zzz 1.0.0 at /run/kevaso-plugins/zzz/plugin.sock refused: dns provider x: plugin aaa serves it already\n", false, ""},
		{"", false, ""},
	} {
		out := run(tc.journal)
		registered, line := Registration("aaa", out)
		if registered != tc.registered || (tc.says == "") != (line == "") || !strings.Contains(line, tc.says) {
			t.Errorf("journal %q: registered %v, line %q", tc.journal, registered, line)
		}
	}
}
