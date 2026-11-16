package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/boottime"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/sdk/kri"
)

// goneEvery is how often a recorded silo the API no longer places here is looked for in the
// runtimes (it stays recorded until none of them has it).
var goneEvery = 10 * time.Second

// The fence record's silos, as this agent keeps them:
//
//   - a silo is recorded before its runtime creates or starts it (recordForFence), never after;
//   - every silo the API places here, or that is moving away from here, is recorded with its
//     StopAfter (fenceEntry);
//   - a recorded silo the API no longer places here stays, with its last policy, until no
//     runtime here has it: a silo moved or deleted while its old copy still runs stays covered.
//
// What an earlier run of the agent recorded stands until this run knows better.

// fenceEntry is how s is recorded for the fence watcher (record version 2): stopped without the
// control plane only if it asked for it, after its own after (§0.7). No onHostLoss, and no fence
// flag on the record (K-067): a watcher from before version 2 (not yet restarted by an upgrade)
// reads those its old way and would stop every Recreate and Move silo; without them it stops
// nothing, and the agent arms nothing for it (no stamp).
func fenceEntry(s *v1.Silo) fence.Silo {
	e := fence.Silo{ID: idOf(s), Runtime: s.Spec.Runtime}
	if stop, after := s.StopsOnControlPlaneLoss(); stop {
		e.StopAfter = after
	}
	return e
}

// armFence says on the silo whether this host's fence stops it (fence.ArmedCondition), only
// once the record on disk holds that: the control plane restarts an opted-in silo elsewhere only
// while it's armed. Without a fence record (no FenceDir) nothing here could stop it, so it is
// never armed.
func (a *Agent) armFence(ctx context.Context, s *v1.Silo) error {
	stop, after := s.StopsOnControlPlaneLoss()
	armed := meta.FindCondition(s.Status.Conditions, fence.ConditionArmed)
	if !stop || a.FenceDir == "" {
		if armed == nil || armed.Status != meta.ConditionTrue {
			return nil
		}
		return a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			meta.SetCondition(&st.Conditions, meta.Condition{Type: fence.ConditionArmed, Status: meta.ConditionFalse, Reason: "NotStopped",
				Message: a.HostName + " doesn't stop this silo without the control plane", ObservedGeneration: s.Generation}, a.now())
		})
	}
	if why, faulted := a.fenceFaulted.Load(s.UID); faulted {
		// K-094: its kill here failed: nothing says this host's fence would stop it next time.
		if armed != nil && armed.Status == meta.ConditionFalse && armed.Reason == "KillFailed" {
			return nil
		}
		a.log("%s/%s: its fence kill here failed (%v): disarmed", s.Namespace, s.Name, why)
		return a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			meta.SetCondition(&st.Conditions, meta.Condition{Type: fence.ConditionArmed, Status: meta.ConditionFalse, Reason: "KillFailed",
				Message:            fmt.Sprintf("the fence on %s couldn't confirm this silo stopped in the last outage (%v): not armed until a kill of it there is confirmed", a.HostName, why),
				ObservedGeneration: s.Generation}, a.now())
		})
	}
	if !a.watcherLive() {
		// No watcher of this version is seen running (K-067): stopped, failed, or one from before
		// an upgrade. Nothing here would stop the silo with the agent gone: not armed.
		if armed == nil || armed.Status != meta.ConditionTrue {
			return nil
		}
		a.log("fence watcher not running (no fresh stamp in %s): disarming %s/%s", a.FenceDir, s.Namespace, s.Name)
		return a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			meta.SetCondition(&st.Conditions, meta.Condition{Type: fence.ConditionArmed, Status: meta.ConditionFalse, Reason: "NoWatcher",
				Message: "the fence watcher on " + a.HostName + " isn't running: nothing would stop this silo without its agent", ObservedGeneration: s.Generation}, a.now())
		})
	}
	if a.keepsKillFailed(s) {
		return nil // the mark survived a restart: still disarmed until a kill here is confirmed
	}
	if fence.Armed(s) && s.Status.Host == a.HostName {
		return nil
	}
	if err := a.recordForFence(s); err != nil { // on disk first
		return err
	}
	return a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		meta.SetCondition(&st.Conditions, fence.ArmedCondition(a.HostName, after, s.Generation), a.now())
	})
}

// killFailedMark reports whether s carries this host's FenceArmed KillFailed condition: the
// durable form of a fence kill that was not confirmed.
func killFailedMark(s *v1.Silo, host string) bool {
	c := meta.FindCondition(s.Status.Conditions, fence.ConditionArmed)
	return c != nil && c.Status == meta.ConditionFalse && c.Reason == "KillFailed" &&
		strings.Contains(c.Message, "the fence on "+host+" couldn't")
}

// keepsKillFailed: the stored mark stands and this process has not confirmed a kill of s since.
// A restart begins with an empty killConfirmed, so the condition is what keeps the silo disarmed.
func (a *Agent) keepsKillFailed(s *v1.Silo) bool {
	if _, ok := a.killConfirmed.Load(s.UID); ok {
		return false
	}
	return killFailedMark(s, a.HostName)
}

// watcherLive: the fence watcher's stamp is fresh, of this boot and record version (K-067).
func (a *Agent) watcherLive() bool {
	if a.FenceDir == "" {
		return false
	}
	st, ok, err := fence.ReadStamp(a.FenceDir)
	return err == nil && ok && fence.Live(st, boottime.ID(), boottime.Now())
}

// recordForFence records s (and writes the record) before its runtime starts it.
func (a *Agent) recordForFence(s *v1.Silo) error {
	if a.FenceDir == "" {
		return nil
	}
	a.fenceMu.Lock()
	defer a.fenceMu.Unlock()
	a.loadRecorded()
	e := fenceEntry(s)
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
	// The fence is inert unless a silo here asked to stop without the control plane (§0.7).
	r := fence.Record{Version: fence.RecordVersion, Written: a.now().UTC(), LastContact: a.fencePrev.LastContact, BootID: boottime.ID()}
	if b, ok := a.contactBoot(); ok {
		r.ContactBoot = b
	}
	if a.LastContact != nil {
		last := a.LastContact()
		if last.IsZero() && !a.started.IsZero() {
			last = a.lastContact() // none yet in this run
		}
		if last.After(r.LastContact) {
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
		a.recorded[s.UID] = fenceEntry(s)
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
			if ok[rt] && !present[uid] && a.absentByName(ctx, rt, a.recorded[uid].ID) {
				delete(a.recorded, uid) // gone from its runtime: only now
			}
		}
	}
	return a.buildRecord()
}

// absentByName says whether runtime rt, asked for id by its name, says cleanly it has nothing of
// it: a silo whose state file can't be read isn't in its List and may still run (K-105).
func (a *Agent) absentByName(ctx context.Context, rt string, id kri.ID) bool {
	r, ok := a.Runtimes[rt]
	if !ok {
		return true
	}
	sctx, cancel := context.WithTimeout(ctx, fence.KillWithin) // a hung engine never stalls the record
	defer cancel()
	st, err := r.Status(sctx, id)
	return err == nil && st.State == kri.Absent
}

// runtimeUIDs is every silo the runtimes here have, and which runtimes could say.
func (a *Agent) runtimeUIDs(ctx context.Context) (present map[string]bool, listed map[string]bool) {
	present, listed = map[string]bool{}, map[string]bool{}
	for name, rt := range a.Runtimes {
		lctx, cancel := context.WithTimeout(ctx, fence.KillWithin) // a hung engine never stalls the record (K-094)
		ids, err := rt.List(lctx)
		cancel()
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

// ConditionFenceUnconfirmed is the Host condition that names the silos this host's own fence
// couldn't confirm stopped during its last outage (K-094).
const ConditionFenceUnconfirmed = "FenceUnconfirmed"
