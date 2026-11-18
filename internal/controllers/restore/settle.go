// Package restore settles a silo after a restored history.
//
// A worker may stop silos, and a copy it is already running stays. It starts nothing it is not
// already running until this controller marks that silo settled. Settlement waits until every
// host the restored store had, and every host the operator says joined since the backup, has
// reported the copies it holds or been confirmed off. One copy is placed on that host. None
// leaves the stored placement. More than one freezes the silo: the placement stays, and every
// disk is kept. A decision is not made again.
package restore

import (
	"reflect"
	"sort"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/moves"
)

// BlocksPlacement reports whether controllers leave this silo's placement and volumes alone.
// A silo created in this history has no earlier copy. A settled one may be placed. Anything
// else from before the history — pending, frozen, or not yet marked — waits.
func BlocksPlacement(s *v1.Silo, g *v1.RestoreGate) bool {
	if s == nil || g == nil || g.Spec.History == "" || createdSince(s, g) {
		return false
	}
	r := s.Status.Restore
	return r == nil || r.History != g.Spec.History || r.Phase != v1.RestoreSettled
}

// HasStatement reports whether the operator said which hosts the backup cannot know.
// Exactly one form: none were added, or the list of those that were.
func HasStatement(g *v1.RestoreGate) bool {
	if g == nil {
		return false
	}
	return g.Spec.NoHostsAdded != (len(g.Spec.HostsAdded) > 0)
}

// MustReport is every host the restored store had, plus every host the operator says joined
// since the backup. A host that appears later is not part of the account.
func MustReport(g *v1.RestoreGate) []string {
	if g == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, n := range g.Spec.Required {
		add(n)
	}
	for _, n := range g.Spec.HostsAdded { // a host joined since the backup is part of the account
		add(n)
	}
	return out
}

// InAccount reports whether name is a host this history is waiting on.
func InAccount(g *v1.RestoreGate, name string) bool {
	for _, n := range MustReport(g) {
		if n == name {
			return true
		}
	}
	return false
}

// ConfirmedOff reports whether the operator said this host is off or wiped.
func ConfirmedOff(g *v1.RestoreGate, name string) bool {
	if g == nil {
		return false
	}
	for _, n := range g.Spec.ConfirmedOff {
		if n == name {
			return true
		}
	}
	return false
}

// Reported reports whether the host has said which copies it holds in this history.
func Reported(g *v1.RestoreGate, h *v1.Host) bool {
	if g == nil || h == nil || h.Status.Copies == nil {
		return false
	}
	c := h.Status.Copies
	return c.Reported && c.History == g.Spec.History
}

// Unreported is the account's hosts that have not reported and are not confirmed off.
func Unreported(g *v1.RestoreGate, hosts []*v1.Host) []string {
	byName := map[string]*v1.Host{}
	for _, h := range hosts {
		if h != nil {
			byName[h.Name] = h
		}
	}
	var out []string
	for _, name := range MustReport(g) {
		if ConfirmedOff(g, name) || Reported(g, byName[name]) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// AccountOpen reports whether any silo from before this history is not settled.
func AccountOpen(g *v1.RestoreGate, silos []*v1.Silo) bool {
	if g == nil || g.Spec.History == "" {
		return false
	}
	for _, s := range silos {
		if BlocksPlacement(s, g) {
			return true
		}
	}
	return false
}

// Settle returns the status this silo should have, and whether it differs.
// A settled or frozen silo is left as it was decided. A silo created in this history is settled
// at once. Without the operator's statement, or while a host in the account has not reported,
// it stays pending and its placement stays. Then: no copy leaves the stored placement, one copy
// is placed on that host, and more than one freezes it.
func Settle(s *v1.Silo, g *v1.RestoreGate, hosts []*v1.Host) (v1.SiloStatus, bool) {
	st := s.Status
	if g == nil || g.Spec.History == "" {
		return st, false
	}
	if r := st.Restore; r != nil && r.History == g.Spec.History && (r.Phase == v1.RestoreSettled || r.Phase == v1.RestoreFrozen) {
		return st, false // decided once: a later report does not move it or unfreeze it
	}
	if createdSince(s, g) { // made in this history: no earlier copy to find
		st.Restore = marked(g.Spec.History, v1.RestoreSettled, nil)
		return st, !restoreSame(s.Status.Restore, st.Restore)
	}
	if !HasStatement(g) { // no statement: nothing this history can settle
		st.Restore = marked(g.Spec.History, v1.RestorePending, nil)
		return st, !restoreSame(s.Status.Restore, st.Restore)
	}
	byName := map[string]*v1.Host{}
	for _, h := range hosts {
		if h != nil {
			byName[h.Name] = h
		}
	}
	var waiting, holders []string
	for _, name := range MustReport(g) {
		if ConfirmedOff(g, name) { // confirmed off: it holds nothing this history will start
			continue
		}
		h := byName[name]
		if !Reported(g, h) {
			waiting = append(waiting, name)
			continue
		}
		for _, c := range h.Status.Copies.Held {
			if c.UID != "" && c.UID == s.UID && c.Namespace == s.Namespace && c.Name == s.Name {
				holders = append(holders, name)
			}
		}
	}
	if len(waiting) > 0 { // a host that has not reported still decides nothing
		st.Restore = marked(g.Spec.History, v1.RestorePending, nil)
		return st, !restoreSame(s.Status.Restore, st.Restore)
	}
	if len(holders) > 1 { // more than one copy: frozen, placement unchanged, every disk kept
		sort.Strings(holders)
		st.Restore = marked(g.Spec.History, v1.RestoreFrozen, holders)
		return st, !statusSame(s.Status, st)
	}
	if len(holders) == 1 {
		st.Restore = marked(g.Spec.History, v1.RestoreSettled, holders)
		if st.Host != holders[0] && !moves.HandingOff(st) { // a handoff in the backup is not cleared here
			st.Host, st.MovingFrom, st.SiloIP, st.Phase = holders[0], "", "", "Scheduled" // the one copy is the placement
			st.Conditions = dropHostConditions(st.Conditions)
		}
		return st, !statusSame(s.Status, st)
	}
	st.Restore = marked(g.Spec.History, v1.RestoreSettled, nil) // no copy anywhere: the stored placement stands
	return st, !statusSame(s.Status, st)
}

func marked(history, phase string, holders []string) *v1.SiloRestore {
	return &v1.SiloRestore{History: history, Phase: phase, Holders: holders}
}

func createdSince(s *v1.Silo, g *v1.RestoreGate) bool {
	if g.Spec.Started.IsZero() || s.CreationTimestamp == nil || s.CreationTimestamp.IsZero() {
		return false
	}
	return !s.CreationTimestamp.Before(g.Spec.Started)
}

func restoreSame(a, b *v1.SiloRestore) bool { return reflect.DeepEqual(a, b) }

func statusSame(a, b v1.SiloStatus) bool { return reflect.DeepEqual(a, b) }

func dropHostConditions(in []meta.Condition) []meta.Condition {
	var out []meta.Condition
	for _, c := range in {
		if !hostCondition(c.Type) {
			out = append(out, c)
		}
	}
	return out
}

func hostCondition(typ string) bool {
	for _, h := range moves.HostConditions {
		if h == typ {
			return true
		}
	}
	return false
}
