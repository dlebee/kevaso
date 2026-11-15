package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/sdk/kri"
)

// ConditionKeptSilos is the Host condition that lists the silos this host keeps although the
// control plane doesn't know them (no delete of them was seen here: a restore from a backup from
// before them, say). They run on, with their data, until an operator decides.
const ConditionKeptSilos = "KeptSilos"

// ConditionControlPlaneBehind is the Host condition of a held worker (§0.7): its control plane is
// older than what it last saw.
const ConditionControlPlaneBehind = "ControlPlaneBehind"

// The worker's side of §0.7's rule for the control plane it trusts (control.md's contract): each
// answer is judged (client.Judge) against the watermark kept on disk.
//
//   - Accept: as usual.
//   - Hold (a control plane older than what this worker saw): keep running every silo as it is,
//     start nothing, remove nothing, apply nothing; keep heartbeating and say so on the Host. It
//     stays held, across restarts, until a new history (or an operator removes the file).
//   - Foreign (another cluster's control plane): ignore it; nothing is applied from it.
//   - NewHistory (a deliberate restore): accepted; what the restored state doesn't know is kept
//     (removeEverywhere keeps a silo the API doesn't know unless its delete was seen here).
//
// An answer with no headers judges nothing.
type Watermark struct {
	mu   sync.Mutex
	path string
	kept client.Watermark
	seen client.ControlPlaneSeen
	last client.Verdict
	// histories counts the histories accepted in this run (Sending).
	histories int64
	log       func(string, ...any)
	// unreadable: the file is there and can't be trusted (why); the worker holds until a person
	// decides, and no answer is judged against it.
	unreadable string
	// saveErr: the last save failed; the worker holds until one succeeds.
	saveErr error
	// notYetSaid: a NotYet answer was logged (once).
	notYetSaid bool
	// judgeFrom: answers to requests sent under an earlier count of histories than this were
	// sent while the file couldn't be read (ReadAgain): judged NotYet, never against nothing.
	judgeFrom int64
	// refusals counts the answers judged Hold or Foreign in this run (acceptedSince).
	refusals int64
}

// answerMark is what the watermark had judged when a request was sent (mark): an answer is one
// this worker accepted, of the history it trusts now, only if nothing was refused and no other
// history accepted since (acceptedSince).
type answerMark struct{ histories, refusals int64 }

func (w *Watermark) mark() answerMark {
	w.mu.Lock()
	defer w.mu.Unlock()
	return answerMark{w.histories, w.refusals}
}

// acceptedSince says whether an answer to a request sent at m may be acted on as proof (a delete,
// a DeletionTimestamp): the worker isn't held, no answer was judged Hold or Foreign since m (the
// client hands such an answer over, and can't say which request it was), and the history is
// still the one accepted when the request was sent. Anything else: not proof of anything.
func (w *Watermark) acceptedSince(m answerMark) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	held := w.kept.Held || w.last == client.Foreign || w.unreadable != "" || w.saveErr != nil
	return !held && w.histories == m.histories && w.refusals == m.refusals
}

// history names the history this worker trusts now (cluster and history; "" before any): a seen
// delete is recorded under it and honoured only under it.
func (w *Watermark) history() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.kept.ClusterID == "" {
		return ""
	}
	return w.kept.ClusterID + "/" + w.kept.History
}

// OpenWatermark reads the watermark kept at path ("": kept in memory only). kevasod makes it once
// and gives it to the client (as its ControlPlane judge), the agent and the worker's network.
func OpenWatermark(path string, log func(string, ...any)) *Watermark {
	if log == nil {
		log = func(string, ...any) {}
	}
	w := &Watermark{path: path, log: log}
	if path == "" {
		return w
	}
	b, err := os.ReadFile(path)
	if why := WatermarkUnreadable(b, err); why != "" {
		// Unreadable: hold, never act on a control plane this worker can't judge, and say so.
		w.unreadable = why
		log("CONTROL-PLANE WATERMARK UNREADABLE: %s: %s. This worker keeps running every silo and starts, removes and applies nothing "+
			"until a person checks its control plane and runs kvoadm host trust-control-plane for this host", path, why)
		return w
	}
	if err == nil {
		_ = json.Unmarshal(b, &w.kept)
		if w.kept.Held {
			log("held (kept on disk): the control plane of cluster %s was older than what this worker saw (history %s, revision %d)", w.kept.ClusterID, w.kept.History, w.kept.Revision)
		}
	}
	return w
}

var _ client.ControlPlaneVerdicts = (*Watermark)(nil)

// ReadAgain reads the file again while it couldn't be trusted (review of K-096, claim 5: a read
// error at start, an EIO or EMFILE that passes, must not hold the worker for the life of the
// process). The file is taken exactly as at start: one that holds a watermark of a cluster is
// judged against from now on (a held one stays held), one that isn't there is first contact (what
// kvoadm host trust-control-plane leaves, and what a restart would see), anything else still
// holds. It says whether the hold for the file ended. The agent never writes the file while it
// can't trust it, so what it reads now is what was there, or what a person put there.
func (w *Watermark) ReadAgain() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.unreadable == "" || w.path == "" {
		return false
	}
	b, err := os.ReadFile(w.path)
	if why := WatermarkUnreadable(b, err); why != "" {
		w.unreadable = why
		return false
	}
	var k client.Watermark
	if err == nil {
		if err := json.Unmarshal(b, &k); err != nil {
			return false // WatermarkUnreadable parsed it: not reached
		}
	}
	w.kept, w.unreadable, w.last = k, "", ""
	w.histories++
	w.judgeFrom = w.histories
	switch {
	case err != nil:
		w.log("control-plane watermark %s: gone (set aside): this worker takes the control plane it reaches next as its first", w.path)
	case k.Held:
		w.log("control-plane watermark %s reads again: held (kept on disk): the control plane of cluster %s was older than what this worker saw (history %s, revision %d)", w.path, k.ClusterID, k.History, k.Revision)
	default:
		w.log("control-plane watermark %s reads again: cluster %s, history %s, revision %d: answers are judged against it", w.path, k.ClusterID, k.History, k.Revision)
	}
	return true
}

// Sending implements client.ControlPlaneJudge: the revision kept as a request leaves, with
// which accepted history it belongs to (a count, in the top 16 bits): an answer whose request
// left under another history is measured against nothing of it.
func (w *Watermark) Sending() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.histories<<48 | min(w.kept.Revision, 1<<48-1)
}

// Answer implements client.ControlPlaneJudge: one answer judged against what was kept when its
// request was sent (K-071).
func (w *Watermark) Answer(sentAt int64, seen client.ControlPlaneSeen) { w.Judged(sentAt, seen, true) }

// Judged implements client.ControlPlaneVerdicts: Answer, judged with client.JudgeStamp, saying
// its verdict. NotYet (no usable stamp, or a system node that hasn't caught up with a restore
// already accepted) changes nothing; the client tries another node. A watermark that can't be
// read, or whose raise can't be saved, judges Hold (K-096).
func (w *Watermark) Judged(sentAt int64, seen client.ControlPlaneSeen, stamped bool) client.Verdict {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.unreadable != "" {
		w.seen = seen // shown on the Host; nothing is judged against a file that can't be read
		w.refusals++
		return client.Hold
	}
	if sentAt>>48 < w.judgeFrom {
		return client.NotYet // sent while the file couldn't be read: what was kept then is unknown
	}
	keptAtSend := sentAt & (1<<48 - 1)
	if sentAt>>48 != w.histories {
		keptAtSend = 0 // sent before the history it's judged against was accepted
	}
	next, v := client.JudgeStamp(w.kept, keptAtSend, seen, stamped)
	if v == client.NotYet {
		if w.last != client.NotYet && !w.notYetSaid {
			w.notYetSaid = true
			w.log("an answer with nothing to act on yet (no stamp, or a system node behind a restore already accepted: epoch %d, kept %d): trying another", seen.Epoch, w.kept.Epoch)
		}
		return v
	}
	if next != w.kept {
		// On disk before it counts (K-096): an answer acted on whose watermark a restart would
		// forget lets an older control plane in between.
		if err := w.save(next); err != nil {
			if w.saveErr == nil {
				w.log("CONTROL-PLANE WATERMARK NOT SAVED: %v: holding (nothing is applied) until it can be", err)
			}
			w.saveErr = err
			w.refusals++
			return client.Hold
		}
		if w.saveErr != nil {
			w.log("control-plane watermark saved again: no longer held for it")
		}
		w.saveErr = nil
	}
	if next.History != w.kept.History || next.ClusterID != w.kept.ClusterID {
		w.histories++
	}
	if v == client.Hold || v == client.Foreign {
		w.refusals++
	}
	if v != w.last {
		switch v {
		case client.Hold:
			w.log("HOLD: the control plane is older than what this worker saw (kept: history %s revision %d epoch %d; seen: history %s revision %d epoch %d): keeping everything as it is",
				w.kept.History, w.kept.Revision, w.kept.Epoch, seen.History, seen.Revision, seen.Epoch)
		case client.Foreign:
			w.log("ignoring a control plane of another cluster (%s; this worker's is %s)", seen.ClusterID, w.kept.ClusterID)
		case client.NewHistory:
			w.log("a new history of cluster %s (epoch %d, a deliberate restore): accepted; what it doesn't know is kept", seen.ClusterID, seen.Epoch)
		}
	}
	w.last, w.seen, w.kept = v, seen, next
	return v
}

// save writes k durably (K-096): a temporary file, flushed to the disk, renamed over the
// watermark, the folder flushed too. Called with mu held.
func (w *Watermark) save(k client.Watermark) error {
	if w.path == "" {
		return nil
	}
	b, err := json.Marshal(k)
	if err != nil {
		return err
	}
	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := w.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, w.path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// Held says whether nothing may be applied from the control plane now (held, or another
// cluster's): the worker's rules, routes and addresses stay as they are too.
func (w *Watermark) Held() bool { return w.blocked() }

// blocked: nothing may be applied from the control plane now (held, or another cluster's).
func (w *Watermark) blocked() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.kept.Held || w.last == client.Foreign || w.unreadable != "" || w.saveErr != nil
}

func (w *Watermark) state() (client.Watermark, client.ControlPlaneSeen, client.Verdict) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.kept, w.seen, w.last
}

// ControlPlaneJudge is the judge of the control plane's answers (client.Client.ControlPlane): the
// worker sets it on every client it uses toward the control plane (the agent's Client included),
// before the client is used.
func (a *Agent) ControlPlaneJudge() client.ControlPlaneJudge { return a.watermark() }

// watermark is the agent's watermark: Watermark, or read from WatermarkFile the first time it's
// needed.
func (a *Agent) watermark() *Watermark {
	a.cpOnce.Do(func() {
		a.cp = a.Watermark
		if a.cp == nil {
			a.cp = OpenWatermark(a.WatermarkFile, a.log)
		}
	})
	return a.cp
}

// ControlPlaneHeld says whether nothing may be applied from the control plane now (§0.7): the
// worker's own changes (rules, routes, leases) follow it too.
func (a *Agent) ControlPlaneHeld() bool { return a.watermark().blocked() }

// watchControlPlane reports the hold on the Host, and keeps asking while blocked so an answer
// that ends it (a new history; the kept cluster again) is seen. When it ends, every silo is
// looked at again.
func (a *Agent) watchControlPlane(ctx context.Context) {
	ticks := a.tick(ctx, fence.CheckEvery)
	// What was last written, and to which control plane (its history count, Watermark.mark): a
	// restore is another store, whose Host holds what the backup had, not what was written here
	// since. Each is written again under a new history (the coordinator's finding on claim 1: a
	// copy kept and listed under one history was never listed under the next).
	const unwritten = "\x00"
	reported := ""        // the condition last written: status and reason
	keptSaid := unwritten // the kept silos last listed
	wasBlocked := false
	wroteTo := a.watermark().mark().histories
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
		a.watermark().ReadAgain() // an unreadable file is read again on every tick (claim 5)
		if h := a.watermark().mark().histories; h != wroteTo {
			wroteTo, reported, keptSaid = h, "", unwritten
		}
		blocked := a.watermark().blocked()
		kept, seen, verdict := a.watermark().state()
		if !blocked && wasBlocked {
			a.log("the control plane is trusted again (%s): looking at every silo", verdict)
			if a.engine != nil {
				a.collectGarbage(ctx, a.engine)
				a.resyncAll()
			}
		}
		wasBlocked = blocked
		if !blocked {
			keptSaid = a.reportKept(ctx, keptSaid)
		}
		cond := a.controlPlaneCondition(kept, seen)
		key := string(cond.Status) + "/" + cond.Reason
		if key == reported {
			continue
		}
		if verdict == client.Foreign && cond.Status == meta.ConditionFalse {
			// Nothing is written to another cluster's control plane; asking keeps the verdict fresh.
			var h v1.Host
			_ = a.Client.Get(ctx, "Host", "", a.HostName, &h)
			continue
		}
		var h v1.Host
		if err := a.Client.Get(ctx, "Host", "", a.HostName, &h); err != nil {
			continue
		}
		if cond.Status == meta.ConditionFalse && meta.FindCondition(h.Status.Conditions, ConditionControlPlaneBehind) == nil {
			reported = key
			continue
		}
		meta.SetCondition(&h.Status.Conditions, cond, a.now().UTC().Truncate(time.Second))
		if err := a.Client.UpdateStatus(ctx, &h); err == nil {
			reported = key
		}
	}
}

// controlPlaneCondition is the Host's ControlPlaneBehind as the watermark says now: held (an older
// control plane), unreadable or not saved (K-096: never silent), or trusted.
func (a *Agent) controlPlaneCondition(kept client.Watermark, seen client.ControlPlaneSeen) meta.Condition {
	w := a.watermark()
	const meanwhile = "Every silo keeps running as it is; nothing is started, removed or applied meanwhile"
	if why := w.Unreadable(); why != "" {
		return meta.Condition{Type: ConditionControlPlaneBehind, Status: meta.ConditionTrue, Reason: "WatermarkUnreadable",
			Message: fmt.Sprintf("this worker's record of its control plane (%s) is unreadable (%s): it can't tell whether this control plane is older than one it saw. %s. "+
				"Check that this host's control plane is the one it last used (not one restored from an older backup outside kvoadm init --restore), "+
				"then run kvoadm host trust-control-plane [USER@]ADDRESS (the address of %s)", w.path, why, meanwhile, a.HostName)}
	}
	if why := w.NotSaved(); why != "" {
		return meta.Condition{Type: ConditionControlPlaneBehind, Status: meta.ConditionTrue, Reason: "WatermarkNotSaved",
			Message: fmt.Sprintf("this worker can't save its record of its control plane (%s): %s. %s, until it can (check the disk of %s)", w.path, why, meanwhile, a.HostName)}
	}
	if kept.Held {
		return meta.Condition{Type: ConditionControlPlaneBehind, Status: meta.ConditionTrue, Reason: "Held",
			Message: fmt.Sprintf("the control plane is older than what this worker saw: kept history %s revision %d (epoch %d), seen history %s revision %d (epoch %d). "+
				"Every silo keeps running as it is and nothing is applied until a deliberate restore (kvoadm init --restore) starts a new history",
				kept.History, kept.Revision, kept.Epoch, seen.History, seen.Revision, seen.Epoch)}
	}
	return meta.Condition{Type: ConditionControlPlaneBehind, Status: meta.ConditionFalse, Reason: "Trusted",
		Message: fmt.Sprintf("cluster %s, history %s, revision %d", kept.ClusterID, kept.History, kept.Revision)}
}

// reportKept lists on the Host the silos kept although the control plane doesn't know them, when
// that changed since said; it returns what is said now. The list is of the copies the runtimes
// hold now (pruneKept): one removed since (by hand, or by this agent) leaves it, and with none
// left the condition goes.
func (a *Agent) reportKept(ctx context.Context, said string) string {
	a.pruneKept(ctx)
	var kept []string
	a.keptNoted.Range(func(_, v any) bool {
		if c, ok := v.(keptCopy); ok {
			kept = append(kept, c.name)
		}
		return true
	})
	kept = append(kept, a.unreadableKept(ctx)...) // K-105: what may run unlisted is named too
	sort.Strings(kept)
	now := strings.Join(kept, ", ")
	if now == said {
		return said
	}
	var h v1.Host
	if err := a.Client.Get(ctx, "Host", "", a.HostName, &h); err != nil {
		return said
	}
	if now == "" {
		if meta.FindCondition(h.Status.Conditions, ConditionKeptSilos) == nil {
			return now // nothing kept, nothing said: nothing to write
		}
		h.Status.Conditions = slices.DeleteFunc(h.Status.Conditions, func(c meta.Condition) bool { return c.Type == ConditionKeptSilos })
	} else {
		meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: ConditionKeptSilos, Status: meta.ConditionTrue, Reason: "NoDeleteSeen",
			Message: "kept running with their disks and volumes, though the control plane doesn't know them (no delete of them was seen here): " + now},
			a.now().UTC().Truncate(time.Second))
	}
	if err := a.Client.UpdateStatus(ctx, &h); err != nil {
		return said
	}
	return now
}

// pruneKept forgets the kept copies their runtime no longer holds (removed by hand, or by this
// agent): what is listed as kept is what the runtimes hold now, never what was once noted. A
// runtime whose list fails says nothing: its copies stay listed.
func (a *Agent) pruneKept(ctx context.Context) {
	noted := false
	a.keptNoted.Range(func(_, _ any) bool { noted = true; return false })
	if !noted {
		return // nothing listed: no runtime is asked
	}
	held := map[string]map[string]bool{} // runtime → the UIDs it holds (only runtimes that answered)
	for name, rt := range a.Runtimes {
		ids, err := rt.List(ctx)
		if err != nil {
			continue
		}
		held[name] = map[string]bool{}
		for _, id := range ids {
			held[name][id.UID] = true
		}
	}
	a.keptNoted.Range(func(k, v any) bool {
		c, _ := v.(keptCopy)
		if rt := a.Runtimes[c.runtime]; c.unlisted && rt != nil {
			// Not in its List (K-105): asked by name; only a clean Absent forgets it.
			if st, err := rt.Status(ctx, c.id); err == nil && st.State == kri.Absent {
				a.keptNoted.Delete(k)
				a.log("%s is no longer on this host: no longer listed as kept", c.name)
			}
			return true
		}
		if uids, answered := held[c.runtime]; answered && !uids[k.(string)] {
			a.keptNoted.Delete(k)
			a.log("%s is no longer on this host: no longer listed as kept", c.name)
		}
		return true
	})
}

// Unreadable is why the watermark file can't be trusted ("" if it can): until a person decides
// (kvoadm host trust-control-plane), the worker holds.
func (w *Watermark) Unreadable() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.unreadable
}

// NotSaved is the error of the last save that failed ("" since one succeeded): until a save
// succeeds the worker holds, and the answer that raised the watermark doesn't count.
func (w *Watermark) NotSaved() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.saveErr == nil {
		return ""
	}
	return w.saveErr.Error()
}

// WatermarkUnreadable says why a watermark file's contents (b, as read with err) can't be trusted:
// "" for a file that holds a watermark of a cluster, or that isn't there at all (first contact).
// Empty, partial, unparsable, or without a cluster all count as unreadable (K-096): never "never
// seen a control plane", which would accept whatever answers next.
func WatermarkUnreadable(b []byte, err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return ""
	case err != nil:
		return err.Error()
	}
	var k client.Watermark
	if err := json.Unmarshal(b, &k); err != nil {
		return "not a watermark: " + err.Error()
	}
	if k.ClusterID == "" {
		return "it names no cluster"
	}
	return ""
}
