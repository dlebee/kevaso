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
// §0.7): for the host it is on, the after its spec says, and its current generation.
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
