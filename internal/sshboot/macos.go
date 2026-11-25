package sshboot

import (
	"context"
	"fmt"
	"strings"
)

// OS is the machine's operating system as uname -s says it, lower case: linux or darwin.
func (c *Conn) OS(ctx context.Context) (string, error) {
	b, err := c.Run(ctx, "uname -s", nil)
	if err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(string(b))), nil
}

// MacOpenSSL is a shell snippet that sets $o to an OpenSSL 3 or later: macOS's own openssl is
// LibreSSL, which can't read an ed25519 key (checked on macOS 26: "unsupported algorithm"), so
// the signature check uses Homebrew's.
const MacOpenSSL = `o=; for p in /opt/homebrew/opt/openssl@3/bin/openssl /opt/homebrew/bin/openssl /usr/local/opt/openssl@3/bin/openssl /usr/local/bin/openssl; do ` +
	`if [ -x "$p" ] && "$p" version | grep -q '^OpenSSL'; then o=$p; break; fi; done; ` +
	`[ -n "$o" ] || { echo 'checking a signature needs OpenSSL 3 or later: brew install openssl@3 (the openssl macOS ships is LibreSSL and cannot check ed25519)'; exit 1; }; `

// VerifyCommand is the command that checks staged against its signature with the pinned key.
func VerifyCommand(goos, staged string) string {
	v := fmt.Sprintf("pkeyutl -verify -pubin -inkey %s -rawin -in %s -sigfile %s", SigningKeyPath, Quote(staged), Quote(staged+".sig"))
	if goos == "darwin" {
		return MacOpenSSL + `"$o" ` + v
	}
	return "openssl " + v
}

// LaunchDaemonsDir is where launchd reads system daemons.
const LaunchDaemonsDir = "/Library/LaunchDaemons"

// InstallLaunchDaemon writes a launchd daemon (owned by root, as launchd insists) and starts it,
// replacing one of the same label that already runs.
func (c *Conn) InstallLaunchDaemon(ctx context.Context, label string, plist []byte) error {
	path := LaunchDaemonsDir + "/" + label + ".plist"
	if err := c.Upload(ctx, path, plist, 0o644); err != nil {
		return err
	}
	_, err := c.Run(ctx, "chown root:wheel "+Quote(path)+" && "+RelaunchScript(label, path), nil)
	return err
}

// RelaunchScript loads the daemon at path under label, replacing a loaded one. launchctl bootout
// returns before the old daemon is gone: a bootstrap right after it fails with "Bootstrap failed:
// 5: Input/output error" and leaves nothing loaded. So it waits (30 s at most) until the label is
// no longer loaded, and tries bootstrap a few times before giving up.
func RelaunchScript(label, path string) string {
	l, p := Quote(label), Quote(path)
	return "(launchctl bootout system/" + l + " 2>/dev/null; true); " +
		"i=0; while launchctl print system/" + l + " >/dev/null 2>&1 && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; " +
		"n=0; until launchctl bootstrap system " + p + "; do n=$((n+1)); [ $n -ge 5 ] && exit 1; sleep 2; done; " +
		"launchctl enable system/" + l + " && launchctl kickstart -k system/" + l
}
