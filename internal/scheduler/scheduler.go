// Package scheduler places silos on hosts (design §3.3): the cluster chooses, workers offer and can
// repel with taints, silos pick. Schedule is a pure function: hosts and existing silos in, one host
// (or the reason for each host it couldn't use) out.
//
// In order, a host must:
//  1. have the worker component, and be Ready;
//  2. have the silo's runtime installed and Ready;
//  3. carry every label in the silo's hostSelector;
//  4. have no NoSchedule taint the silo doesn't tolerate;
//  5. have room: allocatable CPU and memory minus what silos already placed there ask for.
//
// Among the hosts left, it prefers ones without an untolerated PreferNoSchedule taint, then the one
// with the most free memory (spreading silos out), then the name (so it's deterministic).
package scheduler

import (
	"fmt"
	"sort"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Decision is where a silo goes, or why it can't go anywhere yet.
type Decision struct {
	Host     string            // empty: nowhere fits
	Excluded map[string]string // host → the first rule it failed
}

// Message summarises an unschedulable decision for the silo's condition.
func (d Decision) Message() string {
	if d.Host != "" {
		return "scheduled on " + d.Host
	}
	if len(d.Excluded) == 0 {
		return "no hosts with a worker component"
	}
	names := make([]string, 0, len(d.Excluded))
	for h := range d.Excluded {
		names = append(names, h)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, h := range names {
		parts = append(parts, h+": "+d.Excluded[h])
	}
	return "no host fits (" + strings.Join(parts, "; ") + ")"
}

type usage struct {
	cpu int
	mem int64
}

// Schedule picks a host for silo. placed are all silos already assigned (status.host set).
func Schedule(silo *v1.Silo, hosts []*v1.Host, placed []*v1.Silo) (Decision, error) {
	needMem, err := v1.ParseBytes(silo.Spec.Resources.Memory)
	if err != nil {
		return Decision{}, err
	}
	used := map[string]usage{}
	for _, s := range placed {
		if s.Status.Host == "" || (s.Namespace == silo.Namespace && s.Name == silo.Name) {
			continue
		}
		m, err := v1.ParseBytes(s.Spec.Resources.Memory)
		if err != nil {
			continue // already admitted; a bad value can't happen, and must not block scheduling
		}
		u := used[s.Status.Host]
		u.cpu += s.Spec.Resources.CPU
		u.mem += m
		used[s.Status.Host] = u
	}

	type candidate struct {
		name    string
		prefer  bool // no untolerated PreferNoSchedule taint
		freeMem int64
	}
	d := Decision{Excluded: map[string]string{}}
	var fits []candidate
	for _, h := range hosts {
		w := h.Spec.Components.Worker
		if w == nil {
			continue // not a worker: not even a candidate
		}
		if reason := filter(silo, h, w, used[h.Name], needMem); reason != "" {
			d.Excluded[h.Name] = reason
			continue
		}
		allocMem, _ := v1.ParseBytes(h.Status.Allocatable.Memory)
		fits = append(fits, candidate{
			name:    h.Name,
			prefer:  !untoleratedTaint(silo, w.Taints, v1.PreferNoSchedule),
			freeMem: allocMem - used[h.Name].mem - needMem,
		})
	}
	if len(fits) == 0 {
		return d, nil
	}
	sort.Slice(fits, func(i, j int) bool {
		a, b := fits[i], fits[j]
		if a.prefer != b.prefer {
			return a.prefer
		}
		if a.freeMem != b.freeMem {
			return a.freeMem > b.freeMem
		}
		return a.name < b.name
	})
	d.Host = fits[0].name
	return d, nil
}

func filter(silo *v1.Silo, h *v1.Host, w *v1.WorkerSpec, u usage, needMem int64) string {
	if !meta.IsTrue(h.Status.Conditions, "Ready") {
		return "host not Ready"
	}
	if rs, ok := h.Status.Runtimes[silo.Spec.Runtime]; !ok || rs.State != "Ready" {
		installed := false
		for _, r := range w.Runtimes {
			installed = installed || r.Name == silo.Spec.Runtime
		}
		if !installed {
			return "runtime " + silo.Spec.Runtime + " not installed"
		}
		return "runtime " + silo.Spec.Runtime + " not Ready"
	}
	for k, want := range silo.Spec.Placement.HostSelector {
		if got, ok := w.Labels[k]; !ok || got != want {
			return fmt.Sprintf("label %s=%s missing", k, want)
		}
	}
	if untoleratedTaint(silo, w.Taints, v1.NoSchedule) {
		return "taint not tolerated"
	}
	allocMem, err := v1.ParseBytes(h.Status.Allocatable.Memory)
	if err != nil {
		return "allocatable memory unreadable"
	}
	if h.Status.Allocatable.CPU > 0 && u.cpu+silo.Spec.Resources.CPU > h.Status.Allocatable.CPU {
		return fmt.Sprintf("not enough CPU (%d of %d in use, needs %d)", u.cpu, h.Status.Allocatable.CPU, silo.Spec.Resources.CPU)
	}
	if allocMem > 0 && u.mem+needMem > allocMem {
		return fmt.Sprintf("not enough memory (needs %s)", silo.Spec.Resources.Memory)
	}
	return ""
}

func untoleratedTaint(silo *v1.Silo, taints []v1.Taint, effect v1.TaintEffect) bool {
	for _, t := range taints {
		if t.Effect != effect {
			continue
		}
		tolerated := false
		for _, tol := range silo.Spec.Tolerations {
			if tol.Tolerates(t) {
				tolerated = true
				break
			}
		}
		if !tolerated {
			return true
		}
	}
	return false
}
