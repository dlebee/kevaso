package client

import (
	"net/http"
	"strconv"
)

// Every answer of a control plane carries which cluster it is, which history of that cluster, and
// how far its store has come (brainstorm §0.7): a worker uses them to ignore another cluster's
// control plane and to hold when a control plane is older than what it last saw.
const (
	HeaderClusterID = "Kevaso-Cluster-Id" // the cluster's identity: made once, at kvoadm init
	HeaderHistory   = "Kevaso-History"    // the history: made at creation and at each deliberate restore
	HeaderEpoch     = "Kevaso-Epoch"      // 1 at creation, +1 at each deliberate restore
	HeaderRevision  = "Kevaso-Revision"   // the store's revision when the answer was made
)

// ControlPlaneSeen is what one answer said about the control plane that gave it.
type ControlPlaneSeen struct {
	ClusterID string `json:"clusterID"`
	History   string `json:"history"`
	Epoch     int64  `json:"epoch"`
	// Revision is the store's change number. Within one history it never goes down: not with
	// compaction, a leader change, a failover to another system node, an upgrade or the SQLite to
	// etcd move. It goes down after a restore from an older backup (a new history) or when a system
	// node serves a store older than the one it had (same history: hold).
	Revision int64 `json:"revision"`
}

// ParseControlPlane reads the headers; false when the answer carries none (a control plane from
// before them, or the in-process client of a control plane's own components).
func ParseControlPlane(h http.Header) (ControlPlaneSeen, bool) {
	s := ControlPlaneSeen{ClusterID: h.Get(HeaderClusterID), History: h.Get(HeaderHistory)}
	if s.ClusterID == "" || s.History == "" {
		return s, false
	}
	var err error
	if s.Epoch, err = strconv.ParseInt(h.Get(HeaderEpoch), 10, 64); err != nil || s.Epoch < 1 {
		return s, false
	}
	if s.Revision, err = strconv.ParseInt(h.Get(HeaderRevision), 10, 64); err != nil || s.Revision < 0 {
		return s, false
	}
	return s, true
}

// SetControlPlane writes the headers (the control plane's side).
func SetControlPlane(h http.Header, s ControlPlaneSeen) {
	h.Set(HeaderClusterID, s.ClusterID)
	h.Set(HeaderHistory, s.History)
	h.Set(HeaderEpoch, strconv.FormatInt(s.Epoch, 10))
	if s.Revision > 0 {
		h.Set(HeaderRevision, strconv.FormatInt(s.Revision, 10))
	}
}

// Watermark is what a worker keeps (on disk, across its restarts) about the control plane it
// trusts: the cluster, the history, and the highest revision seen in it. Held, once set, stays set
// until a new history is accepted or an operator clears it.
type Watermark struct {
	ClusterID string `json:"clusterID"`
	History   string `json:"history"`
	Epoch     int64  `json:"epoch"`
	Revision  int64  `json:"revision"`
	Held      bool   `json:"held,omitempty"`
}

// Verdict is what a worker does with an answer (Judge).
type Verdict string

const (
	// Accept: act on the answer as usual.
	Accept Verdict = "Accept"
	// NewHistory: a deliberate restore (kvoadm init --restore): accept it, and keep and list
	// anything this worker runs that the restored state doesn't know, never delete it.
	NewHistory Verdict = "NewHistory"
	// Hold: the control plane is older than what this worker saw. Keep running everything, delete
	// nothing, apply nothing new, report it; stay held until a new history is accepted.
	Hold Verdict = "Hold"
	// Foreign: another cluster's control plane: ignore it entirely.
	Foreign Verdict = "Foreign"
)

// Judge is the worker's rule (brainstorm §0.7) for one answer, pure: given what the worker kept
// and what the answer said, the verdict and what to keep now.
//
//   - nothing kept yet: accept and keep it (a worker's first contact, or one from before this rule).
//   - another cluster: Foreign; keep what was kept.
//   - same history: a revision at or above the one kept is Accept (and raises it), unless the
//     worker is held; a lower one is Hold. Held stays until a new history.
//   - another history with an epoch at or above the one kept: NewHistory; keep the new one.
//   - another history with a lower epoch: Hold (an older restore than one already accepted).
func Judge(kept Watermark, seen ControlPlaneSeen) (Watermark, Verdict) {
	return JudgeAnswer(kept, kept.Revision, seen)
}

// ControlPlaneJudge judges a client's answers (Client.ControlPlane): Sending is called just
// before each request is sent, and what it returns comes back to Answer with that request's
// answer. A worker's judge returns the revision it had kept then (JudgeAnswer).
type ControlPlaneJudge interface {
	Sending() int64
	Answer(sentAt int64, seen ControlPlaneSeen)
}

// JudgeAnswer is Judge for an answer whose request was sent when keptAtSend was the revision
// kept (K-071): the store stamps an answer when its request arrives, and answers on one client
// arrive in any order, so a slow answer stamped before a faster later one says nothing about the
// control plane being older. Only an answer below what was kept when it was sent does. Pure.
func JudgeAnswer(kept Watermark, keptAtSend int64, seen ControlPlaneSeen) (Watermark, Verdict) {
	mark := Watermark{ClusterID: seen.ClusterID, History: seen.History, Epoch: seen.Epoch, Revision: seen.Revision}
	switch {
	case kept.ClusterID == "":
		return mark, Accept
	case seen.ClusterID != kept.ClusterID:
		return kept, Foreign
	case seen.History == kept.History:
		if kept.Held || seen.Revision < keptAtSend {
			kept.Held = true
			return kept, Hold
		}
		kept.Revision = max(kept.Revision, seen.Revision)
		return kept, Accept
	case seen.Epoch >= kept.Epoch:
		return mark, NewHistory
	default:
		kept.Held = true
		return kept, Hold
	}
}
