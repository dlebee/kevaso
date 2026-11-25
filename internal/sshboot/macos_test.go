package sshboot

import (
	"strings"
	"testing"
)

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
