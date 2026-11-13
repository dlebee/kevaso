// Package upgrade rolls a new kevasod across a cluster (design §3.1: "kvoadm upgrade rolls Kevaso
// across the cluster in order"; ADR 0006): system nodes first, one at a time, keeping the store's
// healthy majority and waiting for each to come back; then workers a few at a time. A worker's
// kevasod restarts, its silos keep running (each runtime keeps them outside kevasod's process).
//
// Plan is pure; Execute runs a plan through a Driver (kvoadm's pushes the signed binary over SSH,
// the host verifies it, and kevasod restarts).
package upgrade

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Version is a kevasod version: vMAJOR.MINOR.PATCH, with an optional -pre-release.
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

// Parse reads "v0.4.1" or "0.4.1-rc.1".
func Parse(s string) (Version, error) {
	var v Version
	rest := strings.TrimPrefix(strings.TrimSpace(s), "v")
	rest, v.Pre, _ = strings.Cut(rest, "-")
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("version %q: want vMAJOR.MINOR.PATCH", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("version %q: want vMAJOR.MINOR.PATCH", s)
		}
		*[]*int{&v.Major, &v.Minor, &v.Patch}[i] = n
	}
	return v, nil
}

func (v Version) String() string {
	s := fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Compare is -1, 0 or 1 (a pre-release sorts before its release; pre-releases compare as text).
func (v Version) Compare(o Version) int {
	for _, d := range []int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		if d != 0 {
			return sign(d)
		}
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	}
	return sign(strings.Compare(v.Pre, o.Pre))
}

func sign(d int) int {
	if d < 0 {
		return -1
	}
	if d > 0 {
		return 1
	}
	return 0
}

// The version-skew rule (ADR 0006). During a roll, old and new kevasods talk to each other:
//
//  1. an upgrade moves forward only, and by at most one minor version within one major (a major
//     version comes with its own migration; skip no minor);
//  2. system nodes may differ from each other by at most one minor version (the store's contents
//     and the API between them are compatible across one minor);
//  3. an agent is never newer than the oldest system node, and at most one minor older than it
//     (the API is backward compatible for one minor; agents never see an API older than they are).
//
// Hence the order: every system node first, then the workers.

// UpgradeAllowed is rule 1, from a host's current version to the target.
func UpgradeAllowed(from, to Version) error {
	switch {
	case to.Compare(from) < 0:
		return fmt.Errorf("%s → %s is a downgrade", from, to)
	case to.Major != from.Major:
		return fmt.Errorf("%s → %s changes the major version: that release comes with its own migration", from, to)
	case to.Minor-from.Minor > 1:
		return fmt.Errorf("%s → %s skips a minor version: upgrade to v%d.%d first", from, to, from.Major, from.Minor+1)
	}
	return nil
}

// SkewAllowed is rules 2 and 3 for a cluster's versions at one moment.
func SkewAllowed(system, agents []Version) error {
	if len(system) == 0 {
		return nil
	}
	lo, hi := system[0], system[0]
	for _, v := range system[1:] {
		if v.Compare(lo) < 0 {
			lo = v
		}
		if v.Compare(hi) > 0 {
			hi = v
		}
	}
	if hi.Major != lo.Major || hi.Minor-lo.Minor > 1 {
		return fmt.Errorf("system nodes at %s and %s: more than one minor version apart", lo, hi)
	}
	for _, a := range agents {
		if a.Compare(lo) > 0 {
			return fmt.Errorf("an agent at %s is newer than the oldest system node (%s): system nodes upgrade first", a, lo)
		}
		if a.Major != lo.Major || lo.Minor-a.Minor > 1 {
			return fmt.Errorf("an agent at %s is more than one minor version behind the system nodes (%s)", a, lo)
		}
	}
	return nil
}

// Node is a host as the planner needs it.
type Node struct {
	Name      string
	System    bool // has the control-plane component (a light node included)
	StateOnly bool
	Worker    bool
	Version   string
	Ready     bool
	Leader    bool // runs the controllers now: upgraded last of the system nodes
}

// Phase is which part of the roll a step belongs to.
type Phase string

const (
	SystemPhase Phase = "system" // one system node at a time
	WorkerPhase Phase = "worker" // workers, a batch at a time
)

// Step is hosts upgraded together.
type Step struct {
	Phase Phase
	Hosts []string
}

// Plan is a whole roll.
type Plan struct {
	Target  Version
	Steps   []Step
	Current []string // hosts already at the target
	Notes   []string // what to know before going ahead
}

// MakePlan orders the roll to target, or says why it can't happen now. batch is how many workers
// restart at once (at least 1).
func MakePlan(nodes []Node, target string, batch int) (Plan, error) {
	to, err := Parse(target)
	if err != nil {
		return Plan{}, err
	}
	if batch < 1 {
		batch = 1
	}
	p := Plan{Target: to}
	var sys, workers []Node
	var sysVers, agentVers []Version
	voters, ready := 0, 0
	for _, n := range nodes {
		if !n.System && !n.Worker {
			continue
		}
		if n.Version == "" {
			return p, fmt.Errorf("host %s reports no version (its kevasod is older than version reporting, or not up): upgrade it by hand, or wait for it", n.Name)
		}
		from, err := Parse(n.Version)
		if err != nil {
			return p, fmt.Errorf("host %s: %w", n.Name, err)
		}
		if err := UpgradeAllowed(from, to); err != nil {
			return p, fmt.Errorf("host %s: %w", n.Name, err)
		}
		if n.System {
			voters++
			if n.Ready {
				ready++
			}
			sysVers = append(sysVers, from)
		} else {
			agentVers = append(agentVers, from)
		}
		if from.Compare(to) == 0 {
			p.Current = append(p.Current, n.Name)
			continue
		}
		if n.System {
			sys = append(sys, n)
		} else {
			workers = append(workers, n)
		}
	}
	if err := SkewAllowed(sysVers, agentVers); err != nil {
		return p, fmt.Errorf("the cluster is already outside the version-skew rule: %w", err)
	}
	if len(sys) > 0 {
		switch {
		case voters == 1:
			p.Notes = append(p.Notes, "one system node: the API is away while it restarts (silos keep running)")
		case ready < voters:
			// Taking one more down must still leave a healthy majority.
			if ready-1 <= voters/2 {
				return p, fmt.Errorf("%d of %d system nodes are Ready: restarting one more would lose the store's majority; fix the others first", ready, voters)
			}
		case voters == 2:
			return p, errors.New("two system nodes and no third vote: restarting either stops the store; add a light node first (kvoadm host add … --install control-plane --state-only)")
		}
	}
	sort.SliceStable(sys, func(i, j int) bool {
		a, b := sys[i], sys[j]
		if a.Leader != b.Leader {
			return !a.Leader // the leader last: one handover, not one per step
		}
		if a.StateOnly != b.StateOnly {
			return a.StateOnly // light nodes first: the cheapest to restart
		}
		return a.Name < b.Name
	})
	for _, n := range sys {
		p.Steps = append(p.Steps, Step{Phase: SystemPhase, Hosts: []string{n.Name}})
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].Name < workers[j].Name })
	for i := 0; i < len(workers); i += batch {
		var hs []string
		for _, w := range workers[i:min(i+batch, len(workers))] {
			hs = append(hs, w.Name)
		}
		p.Steps = append(p.Steps, Step{Phase: WorkerPhase, Hosts: hs})
	}
	return p, nil
}

// Driver does the work on real hosts (kvoadm's) or fakes (tests).
type Driver interface {
	// Majority says whether the store has a healthy majority with room to restart one system node.
	Majority(ctx context.Context) error
	// Install puts the verified binary on host and restarts its kevasod.
	Install(ctx context.Context, host string) error
	// Healthy waits until host is Ready again and reports version.
	Healthy(ctx context.Context, host string, version Version) error
}

// Execute runs p step by step and stops at the first failure, saying what's done and what's left.
func Execute(ctx context.Context, p Plan, d Driver, report func(string)) error {
	if report == nil {
		report = func(string) {}
	}
	for i, s := range p.Steps {
		left := func() string {
			var hs []string
			for _, r := range p.Steps[i:] {
				hs = append(hs, r.Hosts...)
			}
			return strings.Join(hs, ", ")
		}
		if s.Phase == SystemPhase {
			if err := d.Majority(ctx); err != nil {
				return fmt.Errorf("before %s: %w (not upgraded yet: %s)", s.Hosts[0], err, left())
			}
		}
		var wg sync.WaitGroup
		errs := make([]error, len(s.Hosts))
		for j, h := range s.Hosts {
			wg.Add(1)
			go func(j int, h string) {
				defer wg.Done()
				if err := d.Install(ctx, h); err != nil {
					errs[j] = fmt.Errorf("%s: install: %w", h, err)
					return
				}
				if err := d.Healthy(ctx, h, p.Target); err != nil {
					errs[j] = fmt.Errorf("%s: didn't come back: %w", h, err)
				}
			}(j, h)
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("%w (stopped; not finished: %s)", err, left())
		}
		report(fmt.Sprintf("%s %s: %s", s.Phase, strings.Join(s.Hosts, ", "), p.Target))
	}
	return nil
}
