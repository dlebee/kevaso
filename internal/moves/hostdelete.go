package moves

import (
	"fmt"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

// CondUnschedulable is the silo condition set when its host was deleted and it cannot be
// placed elsewhere. ReasonHostDeleted is that condition's reason.
const (
	CondUnschedulable = "Unschedulable"
	ReasonHostDeleted = "HostDeleted"
)

// PlaceAfterHostDelete reports whether a silo whose host was deleted is placed elsewhere, the
// way kvo move --confirm-fenced would allow for a lost host. place with recreate false: onHostLoss
// Move and every disk and volume can attach elsewhere. place with recreate true: onHostLoss
// Recreate and CheckPolicy allows it. Otherwise it stays. local names the disk and volumes that
// are left on the deleted host, unreachable, not deleted.
func PlaceAfterHostDelete(s *v1.Silo, classes map[string]scheduler.Class) (place, recreate bool, local []string) {
	m := Of(s, classes)
	local = localLeftBehind(s, m)
	switch s.Policy() {
	case v1.OnHostLossMove:
		if m.WithData && !containerRuntime(s.Spec.Runtime) {
			return true, false, nil
		}
	case v1.OnHostLossRecreate:
		if CheckPolicy(s, m) == nil {
			return true, true, nil
		}
	}
	return false, false, local
}

func localLeftBehind(s *v1.Silo, m Movability) []string {
	var out []string
	if !containerRuntime(s.Spec.Runtime) {
		class := s.Spec.Disk.Class
		if class == "" || class == v1.VolumeLocal {
			out = append(out, "its disk")
		}
	}
	for _, name := range m.Local {
		out = append(out, "volume "+name)
	}
	return out
}

// HostDeletedMessage is the Unschedulable/HostDeleted message: the host, local data that is
// no longer reachable, and the two ways out.
func HostDeletedMessage(s *v1.Silo, host string, local []string) string {
	msg := fmt.Sprintf("%s was deleted. This silo is not started anywhere. ", host)
	if len(local) > 0 {
		msg += fmt.Sprintf("%s on %s is no longer reachable; nothing deleted that data. ", strings.Join(local, " and "), host)
	}
	msg += fmt.Sprintf("kvo move silo %s -n %s --to HOST --recreate, or delete the silo.", s.Name, s.Namespace)
	return msg
}

// StuckOnDeletedHost reports the Unschedulable/HostDeleted condition naming host: the silo
// stays there until a person moves it or deletes it, including if a machine of that name joins.
func StuckOnDeletedHost(st v1.SiloStatus, host string) bool {
	c := meta.FindCondition(st.Conditions, CondUnschedulable)
	return host != "" && c != nil && c.Status == meta.ConditionTrue && c.Reason == ReasonHostDeleted &&
		strings.HasPrefix(c.Message, host+" was deleted")
}

// ClassesForList is the class map kvoadm uses when it has no plugins loaded: a named class
// other than local is treated as global, so the list matches "not a local disk". The controller
// uses the plugins' real topology.
func ClassesForList(silos []*v1.Silo) map[string]scheduler.Class {
	out := map[string]scheduler.Class{}
	add := func(class string) {
		if class != "" && class != v1.VolumeLocal {
			out[class] = scheduler.Class{Topology: kplugin.TopologyGlobal}
		}
	}
	for _, s := range silos {
		if s == nil {
			continue
		}
		add(s.Spec.Disk.Class)
		for _, v := range s.Spec.Volumes {
			add(v.Class)
		}
	}
	return out
}

func withoutHostDeleted(conds []meta.Condition) []meta.Condition {
	out := make([]meta.Condition, 0, len(conds))
	for _, c := range conds {
		if c.Type == CondUnschedulable && c.Reason == ReasonHostDeleted {
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
