package sshboot

import (
	"strings"
	"testing"
)

// A reconnect replaces a loaded daemon: bootstrap must wait until bootout has really unloaded it
// (found on a real Mac: the restore's reconnect left kevasod unloaded with "Bootstrap failed: 5").
func TestRelaunchWaitsForBootoutBeforeBootstrap(t *testing.T) {
	s := strings.ReplaceAll(RelaunchScript("com.kevaso.kevasod", "/Library/LaunchDaemons/com.kevaso.kevasod.plist"), "'", "")
	order := []string{"launchctl bootout system/com.kevaso.kevasod", "while launchctl print system/com.kevaso.kevasod",
		"until launchctl bootstrap system /Library/LaunchDaemons/com.kevaso.kevasod.plist", "launchctl enable system/com.kevaso.kevasod",
		"launchctl kickstart -k system/com.kevaso.kevasod"}
	at := -1
	for _, w := range order {
		i := strings.Index(s, w)
		if i < 0 || i < at {
			t.Fatalf("%q missing or out of order:\n%s", w, s)
		}
		at = i
	}
	if !strings.Contains(s, "[ $n -ge 5 ] && exit 1") {
		t.Fatalf("bootstrap retries without a limit:\n%s", s)
	}
}

func TestVerifyCommandPicksAnOpenSSLThatReadsEd25519OnAMac(t *testing.T) {
	linux := VerifyCommand("linux", "/var/lib/kevaso/staging/kevasod")
	if !strings.HasPrefix(linux, "openssl pkeyutl -verify") {
		t.Fatal(linux)
	}
	mac := VerifyCommand("darwin", "/var/lib/kevaso/staging/kevasod")
	// macOS's own openssl is LibreSSL: it can't read an ed25519 key. Homebrew's is looked for by path.
	for _, w := range []string{"/opt/homebrew/opt/openssl@3/bin/openssl", `grep -q '^OpenSSL'`, `"$o" pkeyutl -verify`, "brew install openssl@3"} {
		if !strings.Contains(mac, w) {
			t.Errorf("%q missing:\n%s", w, mac)
		}
	}
	if strings.Contains(mac, "\nopenssl ") || strings.HasPrefix(mac, "openssl ") {
		t.Fatal("a bare openssl on a Mac")
	}
}
