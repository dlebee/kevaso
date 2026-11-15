package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
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
		return client.Hold
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
	reported := "" // the condition last written: status and reason
	keptSaid := "" // the kept silos last listed
	wasBlocked := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
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
// that changed since said; it returns what is said now.
func (a *Agent) reportKept(ctx context.Context, said string) string {
	var kept []string
	a.keptNoted.Range(func(_, v any) bool {
		if name, ok := v.(string); ok {
			kept = append(kept, name)
		}
		return true
	})
	sort.Strings(kept)
	now := strings.Join(kept, ", ")
	if now == said {
		return said
	}
	var h v1.Host
	if err := a.Client.Get(ctx, "Host", "", a.HostName, &h); err != nil {
		return said
	}
	cond := meta.Condition{Type: ConditionKeptSilos, Status: meta.ConditionFalse, Reason: "None", Message: "no silo is kept that the control plane doesn't know"}
	if now != "" {
		cond.Status, cond.Reason = meta.ConditionTrue, "NoDeleteSeen"
		cond.Message = "kept running with their disks and volumes, though the control plane doesn't know them (no delete of them was seen here): " + now
	}
	meta.SetCondition(&h.Status.Conditions, cond, a.now().UTC().Truncate(time.Second))
	if err := a.Client.UpdateStatus(ctx, &h); err != nil {
		return said
	}
	return now
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
