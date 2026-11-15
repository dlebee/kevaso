package kvoadm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"kevaso.com/core/internal/agent"
)

const trustUsage = "usage: kvoadm host trust-control-plane [USER@]ADDRESS --ssh-key PATH [--host-key SHA256:…] [--ssh-port N] [--data DIR] [--yes]"

// WatermarkFile is a worker's record of its control plane, under its data folder (kevasod --data).
const WatermarkFile = "control-plane-watermark.json"

// TrustOptions are kvoadm host trust-control-plane's flags.
type TrustOptions struct {
	InitOptions
	Data string // the worker's data folder (default /var/lib/kevaso)
	Yes  bool
}

func parseTrust(args []string) (TrustOptions, error) {
	o := TrustOptions{Data: "/var/lib/kevaso"}
	var rest []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--yes" || a == "-y":
			o.Yes = true
		case a == "--data" && i+1 < len(args):
			o.Data = args[i+1]
			i++
		default:
			rest = append(rest, a)
		}
	}
	if !path.IsAbs(o.Data) || path.Clean(o.Data) != o.Data || strings.ContainsAny(o.Data, "'\n") {
		return o, fmt.Errorf("--data %q: a clean absolute path\n%s", o.Data, trustUsage)
	}
	t, err := parseTarget(rest)
	if err != nil {
		return o, fmt.Errorf("%w\n%s", err, trustUsage)
	}
	o.InitOptions = t
	if o.SSHKey == "" {
		if h, err := os.UserHomeDir(); err == nil {
			if p := filepath.Join(h, ".kevaso", "ssh", "id_ed25519"); fileExists(p) {
				o.SSHKey = p
			}
		}
	}
	if o.SSHKey == "" {
		return o, errors.New("--ssh-key PATH: kvoadm logs in with a key (no password logins)")
	}
	return o, nil
}

// trustControlPlane: kvoadm host trust-control-plane [USER@]ADDRESS. A worker whose record of its
// control plane is unreadable (K-096: a power cut mid-write, a damaged disk) holds: it keeps every
// silo running and starts, removes and applies nothing, since it can't tell whether the control
// plane it reaches is older than one it saw. Once a person has checked that it isn't, this sets
// the unreadable record aside (kept, renamed) and restarts kevasod, which then takes the control
// plane it reaches as its first. A readable record is never touched: a held worker is released by
// a new history (kvoadm init --restore), not by this.
func trustControlPlane(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	o, err := parseTrust(args)
	if err != nil {
		return err
	}
	in := bufio.NewReader(stdin)
	conn, _, err := dialHost(ctx, o.InitOptions, in, stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return runTrust(ctx, conn, o, in, out)
}

// TrustLookScript prints "absent", or "present" then the file.
func TrustLookScript(file string) string {
	return "if [ -e " + shQuote(file) + " ]; then echo present; cat " + shQuote(file) + "; else echo absent; fi"
}

// TrustSetAsideScript renames the record aside, keeping it, and restarts kevasod.
func TrustSetAsideScript(file string) string {
	return "set -e; f=" + shQuote(file) + `; mv "$f" "$f.unreadable-$(date -u +%Y%m%dT%H%M%SZ)"; systemctl restart kevasod.service; echo done`
}

func runTrust(ctx context.Context, h hostRunner, o TrustOptions, in *bufio.Reader, out io.Writer) error {
	file := path.Join(o.Data, WatermarkFile)
	b, err := h.Run(ctx, TrustLookScript(file), nil)
	if err != nil {
		return fmt.Errorf("reading %s: %w", file, err)
	}
	first, body, _ := strings.Cut(string(b), "\n")
	switch strings.TrimSpace(first) {
	case "absent":
		_, _ = fmt.Fprintf(out, "→ %s has no record of a control plane: nothing to do (it takes the first one it reaches)\n", o.Address)
		return nil
	case "present":
	default:
		return fmt.Errorf("reading %s: unexpected answer %q", file, strings.TrimSpace(first))
	}
	why := agent.WatermarkUnreadable([]byte(body), nil)
	if why == "" {
		return fmt.Errorf("%s on %s is readable: nothing to set aside. A worker held by an older control plane is released by a new history (kvoadm init --restore), not by this command", file, o.Address)
	}
	_, _ = fmt.Fprintf(out, "%s on %s is unreadable (%s).\nkvoadm will keep it as %s.unreadable-TIME and restart kevasod: the worker then trusts the control plane it reaches next as its own.\n"+
		"Do this only once you know that control plane is the newest of this cluster (not one restored from an older backup outside kvoadm init --restore).\n", file, o.Address, why, file)
	if !o.Yes {
		_, _ = fmt.Fprintf(out, "Type yes to go on: ")
		line, _ := readLine(in)
		if strings.TrimSpace(line) != "yes" {
			return errors.New("not confirmed: nothing was changed")
		}
	}
	if b, err := h.Run(ctx, TrustSetAsideScript(file), nil); err != nil || strings.TrimSpace(lastLineString(b)) != "done" {
		return fmt.Errorf("setting %s aside: %v %s", file, err, strings.TrimSpace(string(b)))
	}
	_, _ = fmt.Fprintf(out, "→ set aside; kevasod restarted on %s: it trusts the control plane it reaches next\n", o.Address)
	return nil
}

func lastLineString(b []byte) string {
	l := strings.Split(strings.TrimSpace(string(b)), "\n")
	return l[len(l)-1]
}
