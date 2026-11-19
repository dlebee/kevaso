// Package restore settles a silo after a restored history.
//
// A worker may stop silos, and a copy it is already running stays. It starts nothing it is not
// already running until this controller marks that silo settled. Settlement waits until every
// host the restored store had, and every host the operator says joined since the backup, has
// reported the copies it holds or been confirmed off. A host with no worker component has
// nothing to report: it holds no copies. A report counts only for a host the restored records
// already allow to hold that silo (its stored host, a handoff end, a volume attachment, or a
// host the operator says joined since the backup). One such copy is placed on that host, except
// while the stored host is still live and those records do not already name the holder: then
// the silo freezes, so the report does not move placement and the stored host does not start a
// second copy. A claim from any other host does not count. More than one allowed copy freezes
// the silo, and so does a stored handoff whose only copy is on neither end. The placement stays,
// and every disk is kept. A decision is not made again.
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
// A host with no worker component never runs an agent, so it counts as reported and holds nothing.
func Reported(g *v1.RestoreGate, h *v1.Host) bool {
	if g == nil || h == nil {
		return false
	}
	if noWorker(h) {
		return true
	}
	if h.Status.Copies == nil {
		return false
	}
	c := h.Status.Copies
	return c.Reported && c.History == g.Spec.History
}

// noWorker reports a host that has no worker component: it cannot hold a silo.
func noWorker(h *v1.Host) bool {
	return h != nil && h.Spec.Components.Worker == nil // a host with no worker holds no copies
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
// it stays pending and its placement stays. Then a copy counts only from a host the restored
// records allow. One such copy is placed on that host when that does not start a second copy.
// Anything else that would run it twice, or a handoff whose only copy is on neither end, freezes it.
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
	var waiting, holders, strangers []string
	for _, name := range MustReport(g) {
		if ConfirmedOff(g, name) { // confirmed off: it holds nothing this history will start
			continue
		}
		h := byName[name]
		if !Reported(g, h) {
			waiting = append(waiting, name)
			continue
		}
		if noWorker(h) { // a host with no worker holds nothing
			continue
		}
		for _, c := range h.Status.Copies.Held {
			if c.UID == "" || c.UID != s.UID || c.Namespace != s.Namespace || c.Name != s.Name {
				continue
			}
			if possibleHolder(name, st, g) { // a report counts only where the restored records allow this host
				holders = append(holders, name)
			} else {
				strangers = append(strangers, name)
			}
		}
	}
	if len(waiting) > 0 { // a host that has not reported still decides nothing
		st.Restore = marked(g.Spec.History, v1.RestorePending, nil)
		return st, !restoreSame(s.Status.Restore, st.Restore)
	}
	// A host the records do not allow does not take the silo. While the stored host is live and
	// does not itself hold the copy, settling here would start one on top of the copy that host
	// reports: freeze, and leave the placement.
	if len(strangers) > 0 && !listed(holders, st.Host) && storedLive(g, byName, st.Host) { // a stranger's claim does not start a second copy
		sort.Strings(strangers)
		st.Restore = marked(g.Spec.History, v1.RestoreFrozen, strangers)
		return st, !statusSame(s.Status, st)
	}
	if len(holders) > 1 { // more than one copy the records allow: frozen, placement unchanged, every disk kept
		sort.Strings(holders)
		st.Restore = marked(g.Spec.History, v1.RestoreFrozen, holders)
		return st, !statusSame(s.Status, st)
	}
	if len(holders) == 1 {
		holder := holders[0]
		if moves.HandingOff(st) && holder != st.Host && holder != st.MovingFrom { // the only copy is neither end of the handoff
			st.Restore = marked(g.Spec.History, v1.RestoreFrozen, holders)
			return st, !statusSame(s.Status, st)
		}
		if st.Host != holder && storedLive(g, byName, st.Host) && !recordsName(holder, st) { // a live stored host is not moved by a report alone
			st.Restore = marked(g.Spec.History, v1.RestoreFrozen, holders)
			return st, !statusSame(s.Status, st)
		}
		st.Restore = marked(g.Spec.History, v1.RestoreSettled, holders)
		if st.Host != holders[0] && !moves.HandingOff(st) { // a handoff in the backup is not cleared here
			from := st.Host
			st.Host, st.SiloIP, st.Phase = holders[0], "", "Scheduled" // the one copy is the placement
			st.Conditions = dropHostConditions(st.Conditions)
			followVolumes(&st, from, holders[0], storedLive(g, byName, from))
		}
		return st, !statusSame(s.Status, st)
	}
	st.Restore = marked(g.Spec.History, v1.RestoreSettled, nil) // no counted copy: the stored placement stands
	return st, !statusSame(s.Status, st)
}

// possibleHolder reports whether the restored records already allow name to hold this silo:
// the stored host, the other end of a handoff, a host named on a volume, or a host the operator
// says joined since the backup.
func possibleHolder(name string, st v1.SiloStatus, g *v1.RestoreGate) bool {
	if name == "" {
		return false
	}
	if name == st.Host || name == st.MovingFrom {
		return true
	}
	if g != nil {
		for _, n := range g.Spec.HostsAdded {
			if n == name {
				return true
			}
		}
	}
	return recordsName(name, st)
}

// recordsName reports whether a handoff or a volume attachment already names name.
func recordsName(name string, st v1.SiloStatus) bool {
	if name != "" && name == st.MovingFrom {
		return true
	}
	for _, v := range st.Volumes {
		if v.AttachedTo == name && name != "" {
			return true
		}
	}
	return false
}

// storedLive reports whether the stored host is in this account, not confirmed off, and has reported.
func storedLive(g *v1.RestoreGate, byName map[string]*v1.Host, name string) bool {
	if name == "" || !InAccount(g, name) || ConfirmedOff(g, name) {
		return false
	}
	return Reported(g, byName[name])
}

func listed(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// followVolumes makes provider volumes follow a placement that moved to the holder.
// The handle is kept: a volume is destroyed only with the silo. An old host that is still
// live is left a handoff so it can unmount and let go; the volumes controller then detaches
// and attaches. A stale mount on a host that will not report is cleared so that detach can proceed.
func followVolumes(st *v1.SiloStatus, from, to string, fromAlive bool) {
	handoff := fromAlive && from != "" && from != to && attachedTo(st.Volumes, from)
	if handoff {
		st.MovingFrom = from // the old host unmounts and lets go; the volumes controller then detaches and attaches
	} else {
		st.MovingFrom = ""
	}
	for i := range st.Volumes {
		at := st.Volumes[i].AttachedTo
		if at == "" || at == to {
			continue
		}
		if handoff && at == from {
			continue
		}
		st.Volumes[i].Mounted = false // stale mount: the handle stays, the controller detaches and attaches
	}
}

func attachedTo(vols []v1.VolumeStatus, host string) bool {
	for _, v := range vols {
		if v.AttachedTo == host && host != "" {
			return true
		}
	}
	return false
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
