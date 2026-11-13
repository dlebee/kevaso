package remote

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"kevaso.com/core/internal/hostreset"
)

// The test machine's reset is kvoadm reset's plan and checklist (internal/hostreset), against a
// baseline of the test's own: the machine's fresh state, recorded once in BaselineDir (not one of
// Kevaso's paths, so no reset removes it) before Kevaso ever ran there. The machine has no Docker
// when the baseline is recorded (RecordBaseline refuses it otherwise), so Docker (and podman) is always the
// reset's to remove, and the volume group only ever sits on Kevaso's loop file.

// Where the test's own state lives on the machine.
const (
	BaselineDir  = "/var/lib/kvt-baseline"
	BaselineFile = BaselineDir + "/state"
	HostsMarker  = hostreset.HostsMarker
	StorageImage = hostreset.StorageImage
	UnitPrefix   = hostreset.TestUnitPrefix
)

// Ports are the TCP ports the metal suite opens on the machine (its checklist's last item):
// the API, DNS, ingress, and each test's own (test/e2e/METAL.md lists who opens which).
var Ports = []int{53, 80, 443, 2380, 6443,
	18080, 18081, 18082, 18090, 18091, 18092, 18093, 18095, 18096, 18100, 18110, 18111, 18120, 18121}

// ErrNoBaseline: the machine's fresh state was never recorded.
var ErrNoBaseline = errors.New("no baseline recorded on the machine")

// ErrNotClean: the reset left something behind.
var ErrNotClean = hostreset.ErrNotClean

// State is the machine's state as the reset compares it.
type State = hostreset.State

// TestPaths are what the suite itself writes on the machine (the stand-in internet, the test registry).
var TestPaths = []string{"/var/lib/kvt-inet", "/var/lib/kvt-registry", "/root/.kvt-push"}

// Checklist is the test machine's checklist: everything gone, Docker and the tests' files included.
func Checklist() []hostreset.Check {
	return append(hostreset.Checklist(hostreset.CheckOptions{Ports: Ports, DockerGone: true, PodmanGone: true}),
		hostreset.Check{Name: "no file of the tests is left", Script: `for f in ` + strings.Join(TestPaths, " ") + `; do [ -e "$f" ] && echo "$f"; done; true`})
}

// Plan is the test machine's reset plan, from its baseline and its state now: kvoadm reset's,
// then the tests' own files.
func Plan(base, now State) []hostreset.Step {
	return append(hostreset.Plan(hostreset.PlanInput{Purge: hostreset.Purgeable(base, now), Tables: hostreset.ExtraTables(base, now),
		IPForward: base.IPForward, DockerOurs: true, PodmanOurs: true, Storage: hostreset.StorageLoop}),
		hostreset.Step{Name: "remove the tests' files", Script: "rm -rf " + strings.Join(TestPaths, " ")})
}

// Baseline reads the recorded fresh state.
func (d *Driver) Baseline(ctx context.Context) (State, error) {
	out, err := d.Run(ctx, "cat "+BaselineFile+" 2>/dev/null || true", nil)
	if err != nil {
		return State{}, err
	}
	if strings.TrimSpace(out) == "" {
		return State{}, fmt.Errorf("%w (%s): record it on the freshly installed machine with RecordBaseline", ErrNoBaseline, BaselineFile)
	}
	return hostreset.ParseState(out)
}

// State reads the machine's state now.
func (d *Driver) State(ctx context.Context) (State, error) {
	out, err := d.Run(ctx, hostreset.StateScript, nil)
	if err != nil {
		return State{}, err
	}
	return hostreset.ParseState(out)
}

// RecordBaseline records the machine's fresh state, once. It refuses a machine that already has
// anything of Kevaso's or Docker (the checklist must pass first), so a baseline can't take in
// leftovers. An existing baseline is kept and returned.
func (d *Driver) RecordBaseline(ctx context.Context) (State, error) {
	if b, err := d.Baseline(ctx); err == nil {
		return b, nil
	} else if !errors.Is(err, ErrNoBaseline) {
		return State{}, err
	}
	if err := d.Check(ctx, nil); err != nil {
		return State{}, fmt.Errorf("not recording a baseline on a machine that isn't fresh (reinstall it): %w", err)
	}
	s, err := d.State(ctx)
	if err != nil {
		return State{}, err
	}
	if _, err := d.Run(ctx, "umask 077 && mkdir -p "+BaselineDir+" && cat > "+BaselineFile, []byte(s.Render())); err != nil {
		return State{}, err
	}
	return s, nil
}

// Check runs the checklist (and, with a baseline, the comparison with it).
func (d *Driver) Check(ctx context.Context, base *State) error {
	checks := Checklist()
	outputs := map[string]string{}
	var errs []error
	for _, c := range checks {
		out, err := d.Run(ctx, c.Script, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("check %q: %w", c.Name, err))
			continue
		}
		outputs[c.Name] = out
	}
	var left []string
	if base != nil {
		now, err := d.State(ctx)
		if err != nil {
			errs = append(errs, err)
		} else {
			left = hostreset.Leftovers(*base, now)
		}
	}
	if err := hostreset.Report(checks, outputs, left); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Reset takes everything Kevaso installed off the machine and checks that nothing is left. Every
// step is tried even when one fails; the error names the failed steps and every leftover.
func (d *Driver) Reset(ctx context.Context) error {
	base, err := d.Baseline(ctx)
	if err != nil {
		return err
	}
	now, err := d.State(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, s := range Plan(base, now) {
		if out, err := d.Run(ctx, s.Script, nil); err != nil {
			errs = append(errs, fmt.Errorf("reset step %q: %w: %s", s.Name, err, strings.TrimSpace(out)))
		}
	}
	if err := d.Check(ctx, &base); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
