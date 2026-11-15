package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
)

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
type watermark struct {
	mu   sync.Mutex
	path string
	kept client.Watermark
	seen client.ControlPlaneSeen
	last client.Verdict
	log  func(string, ...any)
}

func loadWatermark(path string, log func(string, ...any)) *watermark {
	w := &watermark{path: path, log: log}
	if path == "" {
		return w
	}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err == nil && json.Unmarshal(b, &w.kept) == nil:
		if w.kept.Held {
			log("held (kept on disk): the control plane of cluster %s was older than what this worker saw (history %s, revision %d)", w.kept.ClusterID, w.kept.History, w.kept.Revision)
		}
	default:
		// Unreadable: hold, never act on a control plane this worker can't judge.
		w.kept = client.Watermark{ClusterID: "unreadable", Held: true}
		log("the control-plane watermark %s is unreadable (%v): holding until it is fixed or removed", path, err)
	}
	return w
}

// observe judges one answer.
func (w *watermark) observe(seen client.ControlPlaneSeen) {
	w.mu.Lock()
	defer w.mu.Unlock()
	next, v := client.Judge(w.kept, seen)
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
	w.last, w.seen = v, seen
	if next == w.kept {
		return
	}
	w.kept = next
	if err := w.save(); err != nil {
		w.log("control-plane watermark: %v", err)
	}
}

// save writes the watermark atomically. Called with mu held.
func (w *watermark) save() error {
	if w.path == "" {
		return nil
	}
	b, err := json.Marshal(w.kept)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return err
	}
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.path)
}

// blocked: nothing may be applied from the control plane now (held, or another cluster's).
func (w *watermark) blocked() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.kept.Held || w.last == client.Foreign
}

func (w *watermark) state() (client.Watermark, client.ControlPlaneSeen, client.Verdict) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.kept, w.seen, w.last
}

// ObserveControlPlane judges one answer of the control plane (client.Client.ControlPlane): the
// worker sets it on every client it uses toward the control plane (the agent's Client included),
// before the client is used.
func (a *Agent) ObserveControlPlane(s client.ControlPlaneSeen) { a.watermark().observe(s) }

// watermark is the agent's watermark, read from WatermarkFile the first time it's needed.
func (a *Agent) watermark() *watermark {
	a.cpOnce.Do(func() { a.cp = loadWatermark(a.WatermarkFile, a.log) })
	return a.cp
}

// ControlPlaneHeld says whether nothing may be applied from the control plane now (§0.7): the
// worker's own changes (rules, routes, leases) follow it too.
func (a *Agent) ControlPlaneHeld() bool { return a.watermark().blocked() }

// watchControlPlane reports the hold on the Host, and keeps asking while blocked so an answer
// that ends it (a new history; the kept cluster again) is seen. When it ends, every silo is
// looked at again.
func (a *Agent) watchControlPlane(ctx context.Context) {
	t := time.NewTicker(fence.CheckEvery)
	defer t.Stop()
	var reported meta.ConditionStatus // the condition status last written
	wasBlocked := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
		want := meta.ConditionFalse
		if kept.Held {
			want = meta.ConditionTrue
		}
		if !blocked && want == reported {
			continue
		}
		if verdict == client.Foreign {
			// Nothing is written to another cluster's control plane; asking keeps the verdict fresh.
			var h v1.Host
			_ = a.Client.Get(ctx, "Host", "", a.HostName, &h)
			continue
		}
		var h v1.Host
		if err := a.Client.Get(ctx, "Host", "", a.HostName, &h); err != nil {
			continue
		}
		if want == reported {
			continue
		}
		if want == meta.ConditionFalse && meta.FindCondition(h.Status.Conditions, ConditionControlPlaneBehind) == nil {
			reported = want
			continue
		}
		cond := meta.Condition{Type: ConditionControlPlaneBehind, Status: want, Reason: "Trusted",
			Message: fmt.Sprintf("cluster %s, history %s, revision %d", kept.ClusterID, kept.History, kept.Revision)}
		if want == meta.ConditionTrue {
			cond.Reason = "Held"
			cond.Message = fmt.Sprintf("the control plane is older than what this worker saw: kept history %s revision %d (epoch %d), seen history %s revision %d (epoch %d). "+
				"Every silo keeps running as it is and nothing is applied until a deliberate restore (kvoadm restore) starts a new history",
				kept.History, kept.Revision, kept.Epoch, seen.History, seen.Revision, seen.Epoch)
		}
		meta.SetCondition(&h.Status.Conditions, cond, a.now().UTC().Truncate(time.Second))
		if err := a.Client.UpdateStatus(ctx, &h); err == nil {
			reported = want
		}
	}
}
