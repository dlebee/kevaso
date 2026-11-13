package kvoadm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"kevaso.com/core/internal/hostreset"
)

// ResetOptions are kvoadm reset's flags.
type ResetOptions struct {
	InitOptions      // the target and the SSH options every command shares
	Yes         bool // don't ask
	Force       bool // go ahead although silos are on the host (their data is lost)
	WipeStorage bool // remove the volume group and its volumes even on a real disk
}

const resetUsage = "usage: kvoadm reset [USER@]ADDRESS --ssh-key PATH [--host-key SHA256:…] [--ssh-port N] [--dry-run] [--yes] [--force] [--wipe-storage]"

func parseReset(args []string) (ResetOptions, error) {
	var o ResetOptions
	var rest []string
	for _, a := range args {
		switch a {
		case "--yes", "-y":
			o.Yes = true
		case "--force":
			o.Force = true
		case "--wipe-storage":
			o.WipeStorage = true
		case "--kevasod", "--worker", "--restore", "--loop-storage", "--storage-device", "--runtime", "--password",
			"--disable-password-login", "--change-root-password", "--internal-ip", "--external-ip":
			return o, fmt.Errorf("%s isn't a reset flag\n%s", a, resetUsage)
		default:
			rest = append(rest, a)
		}
	}
	t, err := parseTarget(rest)
	if err != nil {
		return o, fmt.Errorf("%w\n%s", err, resetUsage)
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
		return o, errors.New("--ssh-key PATH: reset logs in with a key (no password logins)")
	}
	return o, nil
}

// resetCmd: kvoadm reset [USER@]ADDRESS. It takes Kevaso off a machine again (internal/hostreset):
// it looks first and shows what it will remove and keep, asks (--yes: don't), refuses a host with
// silos on it (--force: go ahead), runs the plan, then the checklist, and names anything left.
func resetCmd(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	o, err := parseReset(args)
	if err != nil {
		return err
	}
	in := bufio.NewReader(stdin)
	conn, _, err := dialHost(ctx, o.InitOptions, in, stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(out, "→ connected to %s@%s (host key %s)\n", o.User, o.Address, conn.Fingerprint)
	return runReset(ctx, conn, o, in, out)
}

// hostRunner runs a root shell script on the host (sshboot.Conn).
type hostRunner interface {
	Run(ctx context.Context, cmd string, stdin []byte) ([]byte, error)
}

// runReset is the reset on a connected host.
func runReset(ctx context.Context, h hostRunner, o ResetOptions, in *bufio.Reader, out io.Writer) error {
	raw, err := h.Run(ctx, hostreset.InspectScript, nil)
	if err != nil {
		return fmt.Errorf("looking at the host: %w", err)
	}
	insp, err := hostreset.ParseInspection(string(raw))
	if err != nil {
		return fmt.Errorf("looking at the host: %w", err)
	}
	d, err := hostreset.Decide(insp, hostreset.Flags{Force: o.Force, WipeStorage: o.WipeStorage})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "\nkvoadm reset %s will:\n", o.Address)
	for _, l := range d.Summary {
		_, _ = fmt.Fprintf(out, "  - %s\n", l)
	}
	if len(d.Lost) > 0 {
		_, _ = fmt.Fprintf(out, "\nThese volumes, and the data on them, will be lost:\n")
		for _, v := range d.Lost {
			_, _ = fmt.Fprintf(out, "  %s\n", v)
		}
	}
	_, _ = fmt.Fprintf(out, "\nIt never touches sshd or your SSH keys, the host's own firewall tables, packages Kevaso didn't install, or data outside Kevaso's paths.\n")
	if o.DryRun {
		return ErrDryRun
	}
	if !o.Yes {
		_, _ = fmt.Fprintf(out, "\nType yes to reset %s: ", o.Address)
		line, _ := readLine(in)
		if strings.TrimSpace(line) != "yes" {
			return errors.New("not confirmed: nothing was changed")
		}
	}

	_, _ = fmt.Fprintln(out)
	var failed []string
	for _, s := range hostreset.Plan(d.Plan) {
		if b, err := h.Run(ctx, s.Script, nil); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %s", s.Name, strings.TrimSpace(firstNonEmpty(string(b), err.Error()))))
			_, _ = fmt.Fprintf(out, "✗ %s\n", s.Name)
			continue
		}
		_, _ = fmt.Fprintf(out, "✓ %s\n", s.Name)
	}

	checks := hostreset.Checklist(d.Checks)
	outputs := map[string]string{}
	for _, c := range checks {
		b, err := h.Run(ctx, c.Script, nil)
		if err != nil {
			failed = append(failed, fmt.Sprintf("check %q: %v", c.Name, err))
			continue
		}
		outputs[c.Name] = string(b)
	}
	var left []string
	if insp.Record != nil {
		if b, err := h.Run(ctx, hostreset.StateScript, nil); err == nil {
			if now, err := hostreset.ParseState(string(b)); err == nil {
				left = hostreset.Leftovers(insp.Record.State, now)
			}
		}
	}
	report := hostreset.Report(checks, outputs, left)
	if len(failed) > 0 {
		_, _ = fmt.Fprintf(out, "\nSteps that failed:\n  - %s\n", strings.Join(failed, "\n  - "))
	}
	if report != nil {
		return report
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d step(s) failed, though the checklist found nothing left", len(failed))
	}
	_, _ = fmt.Fprintf(out, "\n→ %s is clean: every checklist item passed. kvoadm init or host add can set it up again.\n", o.Address)
	return nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// recordInstall writes the install record on the host before Kevaso installs anything
// (hostreset.RecordScript): what kvoadm reset will put back.
func recordInstall(ctx context.Context, h hostRunner, say func(string, ...any)) error {
	b, err := h.Run(ctx, hostreset.RecordScript, nil)
	if err != nil {
		return fmt.Errorf("recording the host before the install: %w", err)
	}
	switch strings.TrimSpace(string(b)) {
	case "recorded":
		say("recorded the host as it is (%s), so kvoadm reset can undo this install", hostreset.RecordFile)
	case "kept":
		say("kept the install record from the first install (%s)", hostreset.RecordFile)
	case "older":
		say("Kevaso is already installed here without an install record: kvoadm reset will fall back to its fixed lists")
	default:
		return fmt.Errorf("recording the host before the install: unexpected answer %q", strings.TrimSpace(string(b)))
	}
	return nil
}
