package kvoadm

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// The Mac check runs under sudo -n: it must report the account that logged in, not root.
func TestMacCheckReportsTheLoginUserUnderSudo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	lines := strings.SplitN(checkScriptDarwin, "\n", 7)
	script := strings.Join(lines[4:6], "\n") // the uid and user lines
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "SUDO_UID=501", "SUDO_USER=someone"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != "uid=501\nuser=someone\n" {
		t.Fatalf("under sudo the check reported %q", got)
	}
	facts := map[string]string{"uid": "501", "user": "someone", "arch": "arm64", "os_version": "26"}
	for _, r := range assessMac(facts, Supported{}) {
		if r.What == "account" && r.Level == "fail" {
			t.Fatalf("a sudo'd login user is refused: %+v", r)
		}
	}
}
