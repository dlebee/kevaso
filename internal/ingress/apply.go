package ingress

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"kevaso.com/core/sdk/kic"
)

// Applying a Plan to a proxy from outside. Everything goes through commands run in the controller
// silo by its runtime (the way init steps and daemons run) or through the proxy's admin API on the
// silo's private address: the proxy's image is the vendor's, with nothing of Kevaso in it, and it
// never calls out. The order keeps the running proxy whole whatever happens:
//
//  1. unchanged (the plan this agent last applied, or the config the proxy already has): nothing;
//  2. the supporting files that are missing are written (they're named by their content, so none
//     is one the running config uses);
//  3. the config is written next to its path (PATH.next) and the proxy's own check runs on it;
//  4. refused: PATH.next and the files just added are removed, and the refusal is reported; the
//     running proxy never saw any of it;
//  5. accepted: PATH.next is moved over PATH, the proxy reloads, and the files no plan names any
//     more (a deleted certificate's key) are removed.
//
// File contents go in on the command's stdin, never its arguments, and are never logged.

// Exec runs argv in the controller silo with stdin, and returns its exit code and output.
type Exec func(ctx context.Context, argv []string, stdin []byte) (code int, out string, err error)

// Caller makes a call to the proxy's admin API in the silo, and returns the status and body.
type Caller func(ctx context.Context, c kic.Call) (status int, body string, err error)

// The commands the applier runs in a silo (sh and the usual tools: every proxy image has them).
// Paths are arguments, never part of a script.
var (
	writeScript = `umask 077 && mkdir -p "$(dirname "$1")" && cat > "$1.tmp" && chmod "$2" "$1.tmp" && mv -f "$1.tmp" "$1"`
	listScript  = `mkdir -p "$1" && ls -1 "$1"`
)

// ReadCmd prints a file.
func ReadCmd(p string) []string { return []string{"cat", p} }

// ListCmd lists a folder's names, making it if it isn't there.
func ListCmd(dir string) []string { return []string{"sh", "-c", listScript, "sh", dir} }

// WriteCmd writes stdin to p with mode, atomically (a temporary file renamed over it).
func WriteCmd(p, mode string) []string { return []string{"sh", "-c", writeScript, "sh", p, mode} }

// RemoveCmd removes files.
func RemoveCmd(paths ...string) []string { return append([]string{"rm", "-f"}, paths...) }

// MoveCmd moves a file over another.
func MoveCmd(from, to string) []string { return []string{"mv", "-f", from, to} }

// Result is how one apply went.
type Result struct {
	Hash     string   // the plan now in effect ("" if none is known to be)
	Changed  bool     // something was written and the proxy reloaded
	Rejected string   // the proxy refused the plan (its own words); the last good one stays
	Blamed   []string // the Ingresses the refusal points at, when the driver can tell
}

// Apply makes p take effect in the silo, unless last (the hash of the plan this agent last applied
// there, "" if it doesn't know) says it already has. An error means it couldn't be done now
// (try again); a rejection is a Result.
func Apply(ctx context.Context, exec Exec, call Caller, d kic.Driver, p kic.Plan, last string) (Result, error) {
	hash := p.Hash()
	if last == hash {
		return Result{Hash: hash}, nil
	}
	if p.Config.Path == "" {
		return applyCall(ctx, call, d, p, hash)
	}
	if last == "" { // this agent doesn't know: the proxy may have it already (an agent restart)
		if code, out, err := exec(ctx, ReadCmd(p.Config.Path), nil); err == nil && code == 0 && out == string(p.Config.Data) {
			return Result{Hash: hash}, nil
		}
	}
	run := func(argv []string, stdin []byte) error {
		code, out, err := exec(ctx, argv, stdin)
		if err == nil && code != 0 {
			err = fmt.Errorf("%s: exit %d: %s", argv[0], code, tail(out))
		}
		return err
	}
	var have map[string]bool
	if p.Dir != "" {
		code, out, err := exec(ctx, ListCmd(p.Dir), nil)
		if err != nil {
			return Result{}, err
		}
		if code != 0 {
			return Result{}, fmt.Errorf("list %s: exit %d: %s", p.Dir, code, tail(out))
		}
		have = map[string]bool{}
		for _, n := range strings.Fields(out) {
			have[path.Join(p.Dir, n)] = true
		}
	}
	var added []string
	for _, f := range p.Files {
		if have[f.Path] {
			continue
		}
		if err := run(WriteCmd(f.Path, mode(f)), f.Data); err != nil {
			return Result{}, fmt.Errorf("write %s: %w", f.Path, err)
		}
		added = append(added, f.Path)
	}
	next := p.Config.Path + ".next"
	if err := run(WriteCmd(next, mode(p.Config)), p.Config.Data); err != nil {
		return Result{}, fmt.Errorf("write %s: %w", next, err)
	}
	if len(p.Check) > 0 {
		argv := make([]string, len(p.Check))
		for i, a := range p.Check {
			argv[i] = strings.ReplaceAll(a, kic.ConfigToken, next)
		}
		code, out, err := exec(ctx, argv, nil)
		if err != nil {
			return Result{}, fmt.Errorf("check: %w", err)
		}
		if code != 0 {
			_ = run(RemoveCmd(append([]string{next}, added...)...), nil)
			r := Result{Hash: last, Rejected: tail(strings.ReplaceAll(out, next, p.Config.Path))}
			if r.Rejected == "" {
				r.Rejected = fmt.Sprintf("%s exited %d", argv[0], code)
			}
			if b, ok := d.(kic.Blamer); ok {
				r.Blamed = b.Blame(p, strings.ReplaceAll(out, next, p.Config.Path))
			}
			return r, nil
		}
	}
	if err := run(MoveCmd(next, p.Config.Path), nil); err != nil {
		return Result{}, err
	}
	if len(p.Reload.Exec) > 0 {
		if err := run(p.Reload.Exec, nil); err != nil {
			return Result{}, fmt.Errorf("reload: %w", err)
		}
	} else if p.Reload.Call != nil {
		if r, err := applyCall(ctx, call, d, p, hash); err != nil || r.Rejected != "" {
			return r, err
		}
	}
	if p.Dir != "" {
		want := map[string]bool{}
		for _, f := range p.Files {
			want[f.Path] = true
		}
		var stale []string
		for f := range have {
			if !want[f] {
				stale = append(stale, f)
			}
		}
		if len(stale) > 0 {
			sort.Strings(stale)
			if err := run(RemoveCmd(stale...), nil); err != nil {
				return Result{}, fmt.Errorf("remove old files: %w", err)
			}
		}
	}
	return Result{Hash: hash, Changed: true}, nil
}

func applyCall(ctx context.Context, call Caller, d kic.Driver, p kic.Plan, hash string) (Result, error) {
	if p.Reload.Call == nil {
		return Result{}, fmt.Errorf("driver %s: a plan with neither a config file nor an admin-API call", d.Info().Name)
	}
	if call == nil {
		return Result{}, fmt.Errorf("driver %s needs the proxy's admin API, and this runtime can't reach it", d.Info().Name)
	}
	status, body, err := call(ctx, *p.Reload.Call)
	if err != nil {
		return Result{}, err
	}
	if status < 200 || status > 299 {
		r := Result{Rejected: fmt.Sprintf("%d: %s", status, tail(body))}
		if b, ok := d.(kic.Blamer); ok {
			r.Blamed = b.Blame(p, body)
		}
		return r, nil
	}
	return Result{Hash: hash, Changed: true}, nil
}

func mode(f kic.File) string {
	m := f.Mode.Perm()
	if m == 0 {
		m = 0o644
	}
	if f.Secret {
		m &= 0o700
	}
	return fmt.Sprintf("%04o", m)
}

// tail is the end of a command's output, enough to say why.
func tail(s string) string {
	s = string(bytes.TrimSpace([]byte(s)))
	if len(s) > 2000 {
		s = "…" + s[len(s)-2000:]
	}
	return s
}
