package kvoadm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"kevaso.com/core/internal/hostreset"
)

// ResetOptions are kvoadm reset's flags.
type ResetOptions struct {
	InitOptions      // the target and the SSH options every command shares
	Yes         bool // don't ask
	Force       bool // go ahead although silos are on the host (their data is lost)
	WipeStorage bool // remove the volume group and its volumes even on a real disk, or with no silo using them
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
	prepareTarget(targetCluster(ctx), &o.InitOptions) // the cluster folder's key, when none is given
	if o.SSHKey == "" {
		return errors.New("--ssh-key PATH: reset logs in with a key (no password logins)")
	}
	in := bufio.NewReader(stdin)
	conn, used, _, err := dialHostUsed(ctx, o.InitOptions, in, stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	// By a host's name, who and where it logged in (a Mac's reset needs its own user, not root).
	o.User, o.Address, o.SSHPort = used.User, used.Address, used.SSHPort
	_, _ = fmt.Fprintf(out, "→ connected to %s@%s (host key %s)\n", o.User, o.Address, conn.Fingerprint)
	if goos, err := conn.OS(ctx); err == nil && goos == "darwin" {
		return runMacReset(ctx, conn, o, in, out)
	}
	return runReset(ctx, conn, o, in, out)
}

// hostRunner runs a root shell script on the host (sshboot.Conn).
type hostRunner interface {
	Run(ctx context.Context, cmd string, stdin []byte) ([]byte, error)
}

// How long reset waits for silos still on the host to go before it refuses: right after
// `kvo delete silo`, the worker is still stopping them (a microVM's unit takes a few seconds).
var resetSiloWait, resetSiloPoll = 30 * time.Second, 3 * time.Second

// waitSilosStopped looks at the host again until no silo is left on it, for up to resetSiloWait,
// and then decides with what it found. Silos that are still there are refused as before, with how
// long it waited, so a reset never takes down a silo that is meant to run (that's --force).
func waitSilosStopped(ctx context.Context, h hostRunner, o ResetOptions, insp hostreset.Inspection, out io.Writer) (hostreset.Decision, error) {
	_, _ = fmt.Fprintf(out, "→ silos are still on the host (%s): waiting up to %s, in case they're still stopping after a delete\n", strings.Join(insp.Silos, ", "), resetSiloWait)
	deadline := time.Now().Add(resetSiloWait)
	for {
		select {
		case <-ctx.Done():
			return hostreset.Decision{}, ctx.Err()
		case <-time.After(resetSiloPoll):
		}
		raw, err := h.Run(ctx, hostreset.InspectScript, nil)
		if err != nil {
			return hostreset.Decision{}, fmt.Errorf("looking at the host: %w", err)
		}
		if insp, err = hostreset.ParseInspection(string(raw)); err != nil {
			return hostreset.Decision{}, fmt.Errorf("looking at the host: %w", err)
		}
		d, err := hostreset.Decide(insp, hostreset.Flags{Force: o.Force, WipeStorage: o.WipeStorage})
		if !errors.Is(err, hostreset.ErrSilos) {
			if err == nil {
				_, _ = fmt.Fprintln(out, "→ they stopped")
			}
			return d, err
		}
		if time.Now().After(deadline) {
			return d, fmt.Errorf("%w (kvoadm waited %s: they are running, not stopping)", err, resetSiloWait)
		}
	}
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
	if errors.Is(err, hostreset.ErrSilos) {
		d, err = waitSilosStopped(ctx, h, o, insp, out)
	}
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
	plan := hostreset.Plan(d.Plan)
	// Stop kevasod first, so nothing new is placed or made here, confirm it is stopped (review
	// claim 4: a stop that said it was done may still leave a process), then look again
	// (review, check-then-act claim 3): the host was shown before the prompt, which can wait for
	// ever. kevasod or its fence still running, or a silo or volume that wasn't shown, stops the
	// reset before anything is removed.
	if len(plan) > 0 && plan[0].Name == hostreset.StopStep {
		if b, err := h.Run(ctx, plan[0].Script, nil); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %s", plan[0].Name, strings.TrimSpace(firstNonEmpty(string(b), err.Error()))))
			markStep(out, false, plan[0].Name, nil)
		} else {
			markStep(out, true, plan[0].Name, b)
		}
		plan = plan[1:]
		if running, err := stillRunning(ctx, h); err != nil || running != "" {
			_, _ = h.Run(ctx, hostreset.StartAgainScript, nil)
			if err != nil {
				return fmt.Errorf("looking whether kevasod stopped: %w (kevasod is started again; nothing was removed)", err)
			}
			return fmt.Errorf("kevasod or its fence still runs after it was stopped: %s. Nothing was removed and kevasod is started again: stop it (systemctl disable --now kevasod kevaso-fence), then run kvoadm reset again", running)
		}
		if changed, err := lookAgain(ctx, h, insp, d, o); err != nil || changed != "" {
			_, _ = h.Run(ctx, hostreset.StartAgainScript, nil)
			if err != nil {
				return fmt.Errorf("looking at the host again before removing anything: %w (kevasod is started again; nothing was removed)", err)
			}
			return fmt.Errorf("the host changed since it was shown: %s. Nothing was removed and kevasod is started again: run kvoadm reset again to see what it would remove now", changed)
		}
	}
	for _, s := range plan {
		if s.Name == hostreset.RecordStep && len(failed) > 0 {
			_, _ = fmt.Fprintf(out, "- %s: kept, since a step failed, so the next reset knows what to clean. Run kvoadm reset again once it is fixed\n", s.Name)
			continue
		}
		// Right before each step that removes a silo's data: kevasod and its fence still don't
		// run (the kill steps end in true too); right before the storage goes, the host is looked
		// at again as well. Otherwise the reset stops here: what is left stays.
		if s.Destructive {
			why := ""
			if running, err := stillRunning(ctx, h); err != nil {
				why = "looking whether kevasod runs: " + err.Error()
			} else if running != "" {
				why = "kevasod or its fence runs again: " + running
			}
			if why == "" && s.Storage {
				if changed, err := lookAgain(ctx, h, insp, d, o); err != nil {
					why = "looking at the host again: " + err.Error()
				} else if changed != "" {
					why = "the host changed since it was shown: " + changed
				}
			}
			if why != "" {
				_, _ = fmt.Fprintf(out, "✗ %s: not run\n", s.Name)
				return fmt.Errorf("the reset stopped before %q: %s. That step and the ones after it weren't run (what they remove is still there): run kvoadm reset again to see what it would remove now", s.Name, why)
			}
		}
		b, err := h.Run(ctx, s.Script, nil)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %s", s.Name, strings.TrimSpace(firstNonEmpty(string(b), err.Error()))))
			markStep(out, false, s.Name, nil)
			continue
		}
		markStep(out, true, s.Name, b)
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
				left = hostreset.LeftoversExcept(insp.Record.State, now, d.NotOurs) // left on purpose: not Kevaso's (K-113)
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

// stillRunning says what of kevasod and its fence runs on the host ("" if nothing): the units'
// states and main processes, and every kevasod process (hostreset.StillRunningScript).
func stillRunning(ctx context.Context, h hostRunner) (string, error) {
	b, err := h.Run(ctx, hostreset.StillRunningScript, nil)
	if err != nil {
		return "", err
	}
	var lines []string
	for l := range strings.Lines(string(b)) {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "; "), nil
}

// lookAgain inspects the host once more and says what it has now that wasn't shown ("" if
// nothing): a silo, or a volume whose data would be lost.
func lookAgain(ctx context.Context, h hostRunner, before hostreset.Inspection, shown hostreset.Decision, o ResetOptions) (string, error) {
	raw, err := h.Run(ctx, hostreset.InspectScript, nil)
	if err != nil {
		return "", err
	}
	now, err := hostreset.ParseInspection(string(raw))
	if err != nil {
		return "", err
	}
	var news []string
	for _, s := range now.Silos {
		if !slices.Contains(before.Silos, s) {
			news = append(news, "silo "+s)
		}
	}
	d, derr := hostreset.Decide(now, hostreset.Flags{Force: true, WipeStorage: o.WipeStorage})
	if derr != nil {
		return "", derr
	}
	for _, v := range d.Lost {
		if !slices.Contains(shown.Lost, v) {
			news = append(news, "volume "+v)
		}
	}
	return strings.Join(news, ", "), nil
}

// markStep prints a step's result. On success it also prints what the step wrote, one line
// indented: a restart says which foreign containers it started again.
func markStep(out io.Writer, ok bool, name string, b []byte) {
	mark := "✓"
	if !ok {
		mark = "✗"
	}
	_, _ = fmt.Fprintf(out, "%s %s\n", mark, name)
	if !ok {
		return
	}
	for l := range strings.Lines(string(b)) {
		if l = strings.TrimSpace(l); l != "" {
			_, _ = fmt.Fprintf(out, "  %s\n", l)
		}
	}
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
