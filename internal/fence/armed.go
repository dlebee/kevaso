package fence

import (
	"fmt"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// ConditionArmed is the silo condition a host's agent writes when its fence will stop that silo
// after `after` without the control plane (onControlPlaneLoss: Stop, record version 2). The
// control plane restarts an opted-in silo elsewhere only while Armed holds for it (brainstorm
// §0.7): for the host it is on, the after its spec says, and its current generation; and only
// once that host also reported the stop itself (ConditionStopped).
const ConditionArmed = "FenceArmed"

// ReasonArmed is ArmedCondition's reason.
const ReasonArmed = "StopsAfter"

// ArmedCondition is the condition the agent on host writes for a silo whose fence record entry
// it has written with StopAfter after, for the silo's generation. The agent writes it only once
// the record holding that entry is on disk, and removes it (or sets it False) when it no longer
// fences the silo.
func ArmedCondition(host string, after time.Duration, generation int64) meta.Condition {
	return meta.Condition{Type: ConditionArmed, Status: meta.ConditionTrue, Reason: ReasonArmed, ObservedGeneration: generation,
		Message: armedMessage(host, after)}
}

func armedMessage(host string, after time.Duration) string {
	return fmt.Sprintf("%s stops this silo after %s without the control plane", host, after)
}

// Armed reports whether the silo's host has armed its fence for the silo as it is now: the
// condition is the one ArmedCondition makes for status.host, the after its spec says, and its
// generation. A condition left by another host (before a move) or for an older spec doesn't count.
func Armed(s *v1.Silo) bool {
	stops, after := s.StopsOnControlPlaneLoss()
	c := meta.FindCondition(s.Status.Conditions, ConditionArmed)
	return stops && c != nil && c.Status == meta.ConditionTrue && c.Reason == ReasonArmed &&
		c.ObservedGeneration == s.Generation && c.Message == armedMessage(s.Status.Host, after)
}

// ConditionStopped is the silo condition a host's agent writes once its fence has stopped the
// silo there and the runtime confirmed nothing of it runs: the host's own report that this copy
// is stopped. It names the start claim stored on the silo when it was written (or that none
// stood), so it stands only while that claim does: every start writes a new claim first (K-015),
// so a report from before a start no longer matches. The control plane restarts an opted-in silo
// elsewhere (onHostLoss), or ends a handoff whose source is gone (K-119), only while this stands
// for that host. Silence alone, however long, never says the copy stopped: a fence whose kill
// failed can't say so, and its host may be cut off.
const ConditionStopped = "FenceStopped"

// ReasonStopped is StoppedCondition's reason.
const ReasonStopped = "StoppedByFence"

// StoppedCondition is the condition the agent on host writes for a silo its fence stopped: claim
// is the silo's standing start claim as stored (nil: none stands), generation its generation.
func StoppedCondition(host string, claim *meta.Condition, generation int64) meta.Condition {
	start := "no start claim stood"
	if claim != nil {
		generation, start = claim.ObservedGeneration, fmt.Sprintf("the start claimed as %q", claim.Message)
	}
	return meta.Condition{Type: ConditionStopped, Status: meta.ConditionTrue, Reason: ReasonStopped, ObservedGeneration: generation,
		Message: fmt.Sprintf("%s (confirmed by its runtime) without the control plane; %s", StoppedPrefix(host), start)}
}

// StoppedPrefix is how a StoppedCondition of host begins: a host writes one only in its own name.
func StoppedPrefix(host string) string { return host + "'s fence stopped this silo" }

// StoppedBy reports whether host reported its fence stopped s as it stands: the condition
// StoppedCondition makes for host, claim (s's standing start claim, nil: none) and s's generation.
// One written before the latest start (another claim), or by another host, doesn't count.
func StoppedBy(s *v1.Silo, host string, claim *meta.Condition) bool {
	want := StoppedCondition(host, claim, s.Generation)
	c := meta.FindCondition(s.Status.Conditions, ConditionStopped)
	return host != "" && c != nil && c.Status == meta.ConditionTrue && c.Reason == ReasonStopped &&
		c.ObservedGeneration == want.ObservedGeneration && c.Message == want.Message
}
