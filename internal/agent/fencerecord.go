package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
)

// goneEvery is how often a recorded silo the API no longer places here is looked for in the
// runtimes (it stays recorded until none of them has it).
var goneEvery = 10 * time.Second

// The fence record's silos, as this agent keeps them:
//
//   - a silo is recorded before its runtime creates or starts it (recordForFence), never after;
//   - every silo the API places here, or that is moving away from here, is recorded with its
//     current policy;
//   - a recorded silo the API no longer places here stays, with its last policy, until no
//     runtime here has it: a silo moved or deleted while its old copy still runs stays covered.
//
// What an earlier run of the agent recorded stands until this run knows better.

// recordForFence records s (and writes the record) before its runtime starts it.
func (a *Agent) recordForFence(s *v1.Silo) error {
	if a.FenceDir == "" {
		return nil
	}
	a.fenceMu.Lock()
	defer a.fenceMu.Unlock()
	a.loadRecorded()
	e := fence.Silo{ID: idOf(s), Runtime: s.Spec.Runtime, OnHostLoss: s.Policy()}
	if a.recorded[s.UID] == e {
		return nil
	}
	a.recorded[s.UID] = e
	if err := fence.Write(a.FenceDir, a.buildRecord()); err != nil {
		return fmt.Errorf("fence record (needed before the silo starts): %w", err)
	}
	return nil
}

func (a *Agent) loadRecorded() {
	if a.recorded != nil {
		return
	}
	a.recorded = map[string]fence.Silo{}
	for _, s := range a.fencePrev.Silos {
		a.recorded[s.ID.UID] = s
	}
}

// buildRecord is the record from what's recorded now. Called with fenceMu held.
func (a *Agent) buildRecord() fence.Record {
	r := fence.Record{Written: a.now().UTC(), LastContact: a.fencePrev.LastContact, Fence: a.fenceApplies()}
	if a.LastContact != nil {
		if last := a.LastContact(); last.After(r.LastContact) {
			r.LastContact = last.UTC()
		}
	}
	for _, s := range a.recorded {
		r.Silos = append(r.Silos, s)
	}
	sort.Slice(r.Silos, func(i, j int) bool { return r.Silos[i].ID.UID < r.Silos[j].ID.UID })
	return r
}

// fenceRecord brings the recorded silos up to date with the API and the runtimes, and returns the
// record.
func (a *Agent) fenceRecord(ctx context.Context) fence.Record {
	a.fenceMu.Lock()
	defer a.fenceMu.Unlock()
	a.loadRecorded()
	if a.silos == nil || !a.silosSynced.Load() {
		return a.buildRecord()
	}
	here := map[string]bool{}
	for _, o := range a.silos.List() {
		s := o.(*v1.Silo)
		if s.Status.Host != a.HostName && s.Status.MovingFrom != a.HostName {
			continue
		}
		here[s.UID] = true
		a.recorded[s.UID] = fence.Silo{ID: idOf(s), Runtime: s.Spec.Runtime, OnHostLoss: s.Policy()}
	}
	var gone []string
	for uid := range a.recorded {
		if !here[uid] {
			gone = append(gone, uid)
		}
	}
	if len(gone) > 0 && a.now().Sub(a.goneChecked) >= goneEvery {
		a.goneChecked = a.now()
		present, ok := a.runtimeUIDs(ctx)
		for _, uid := range gone {
			rt := a.recorded[uid].Runtime
			if ok[rt] && !present[uid] {
				delete(a.recorded, uid) // gone from its runtime: only now
			}
		}
	}
	return a.buildRecord()
}

// runtimeUIDs is every silo the runtimes here have, and which runtimes could say.
func (a *Agent) runtimeUIDs(ctx context.Context) (present map[string]bool, listed map[string]bool) {
	present, listed = map[string]bool{}, map[string]bool{}
	for name, rt := range a.Runtimes {
		ids, err := rt.List(ctx)
		if err != nil {
			continue
		}
		listed[name] = true
		for _, id := range ids {
			present[id.UID] = true
		}
	}
	return present, listed
}

func (a *Agent) writeFenceRecord(ctx context.Context) {
	if a.FenceDir == "" {
		return
	}
	r := a.fenceRecord(ctx)
	a.fenceMu.Lock()
	err := fence.Write(a.FenceDir, r)
	a.fenceMu.Unlock()
	if err != nil {
		a.log("fence record: %v", err)
	}
}

// reportFenceFaults: once in contact, what the watcher found during its last fence (running silos
// with no recorded policy, which it couldn't stop) goes on this host's Host as condition
// FenceFaults, and the watcher's report is removed.
func (a *Agent) reportFenceFaults(ctx context.Context) {
	if a.FenceDir == "" || a.Client == nil {
		return
	}
	f, ok, err := fence.ReadFaults(a.FenceDir)
	if err != nil || !ok {
		return
	}
	cond := meta.Condition{Type: fence.ConditionFaults, Status: meta.ConditionFalse, Reason: "AllRecorded",
		Message: "the last fence (" + f.At.UTC().Format(time.RFC3339) + ") found every running silo recorded"}
	if len(f.Silos) > 0 {
		names := make([]string, 0, len(f.Silos))
		for _, s := range f.Silos {
			names = append(names, s.ID.String()+" ("+s.Runtime+")")
		}
		cond.Status, cond.Reason = meta.ConditionTrue, "UnrecordedSilos"
		cond.Message = "the fence at " + f.At.UTC().Format(time.RFC3339) + " found running silos with no recorded policy and left them running: " +
			strings.Join(names, ", ") + ". If the control plane started them elsewhere, two copies ran."
		a.log("FENCE FAULT reported: %s", cond.Message)
	}
	var h v1.Host
	if err := a.Client.Get(ctx, "Host", "", a.HostName, &h); err != nil {
		return
	}
	meta.SetCondition(&h.Status.Conditions, cond, a.now().UTC().Truncate(time.Second))
	if err := a.Client.UpdateStatus(ctx, &h); err != nil {
		return // a conflict with the heartbeat: next second
	}
	if err := fence.RemoveFaults(a.FenceDir); err != nil {
		a.log("fence faults: %v", err)
	}
}
