package tart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Licence is said once at install and kept in the runtime's version line: Tart is FSL-1.1-ALv2.
const Licence = "Tart is licensed FSL-1.1-ALv2 (no competing commercial use; each release becomes Apache 2.0 after two years); Kevaso only runs the program you installed"

// ErrNoTart: the tart program isn't on this Mac.
var ErrNoTart = errors.New("tart isn't installed: as the user kevasod runs as, run: brew install openai/tools/tart")

var versionRE = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

// softnetCheck passes when softnet is installed and runs as root without a password (a sudoers
// rule for that one binary) or is setuid root (E042: Tart starts it through sudo).
const softnetCheck = `p=$(command -v softnet) || exit 3
if [ -u "$p" ] && [ "$(stat -f %u "$p")" = 0 ]; then exit 0; fi
sudo -n "$p" --version >/dev/null 2>&1 || exit 4`

// Install readies the host: the tart program is there, its version is known, the state folder is
// made, and (with Softnet) the packet filter can run as root. Kevaso installs nothing by itself
// on a Mac: Homebrew refuses root, and Tart's licence is the operator's to accept.
func (r *Runtime) Install(ctx context.Context, progress func(string)) error {
	if progress == nil {
		progress = func(string) {}
	}
	var out bytes.Buffer
	code, err := r.Host.Run(ctx, r.cmd("--version").with(&out, &out, nil))
	if err != nil {
		if strings.Contains(err.Error(), "not found") || errors.Is(err, os.ErrNotExist) {
			return ErrNoTart
		}
		return fmt.Errorf("tart --version: %w", err) // e.g. the host's command folder can't be made
	}
	if code != 0 {
		return ErrNoTart
	}
	v := versionRE.FindString(out.String())
	if v == "" {
		return fmt.Errorf("tart --version: %q: no version", strings.TrimSpace(out.String()))
	}
	r.mu.Lock()
	r.versions = v
	r.mu.Unlock()
	if r.Softnet {
		var so bytes.Buffer
		code, err := r.Host.Run(ctx, Cmd{Name: "sh", Args: []string{"-c", softnetCheck}, Stdout: &so, Stderr: &so})
		if err != nil || code != 0 {
			return errors.New("softnet can't run as root: allow it with a sudoers rule for that one binary " +
				"(<user> ALL=(root) NOPASSWD: /opt/homebrew/bin/softnet), or start kevasod with --tart-softnet=false to run silos without the packet filter (silos then reach each other and your LAN)")
		}
	}
	if err := r.Host.WriteFile(r.dir()+"/.keep", nil, 0o600); err != nil {
		return fmt.Errorf("tart: state folder %s: %w", r.dir(), err)
	}
	progress("tart " + v + " ready (macOS silos, at most " + fmt.Sprint(MaxRunning) + " running per Mac). " + Licence)
	return nil
}
