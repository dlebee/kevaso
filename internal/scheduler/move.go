package scheduler

import (
	"slices"
	"sort"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

// Movability is where a placed silo could move: the area its ways in allow, and the hosts that
// would take it now (by every rule, as a move to one of them is judged).
type Movability struct {
	Area Area
	// Wait: why it can't be placed anywhere now (it goes ahead by itself once that changes).
	Wait string
	// To are the other hosts that would take it now, sorted.
	To []string
	// Excluded are the other hosts in the area that wouldn't, and why.
	Excluded map[string]string
	// Host is where it is now.
	Host string
}

// CanMove says where silo could move from where it is (status.host) to, and why not elsewhere:
// what kvo describe silo prints as "can move: … (why)". hosts are all hosts; placed, all placed
// silos (as Schedule). Pure.
func CanMove(silo *v1.Silo, hosts []*v1.Host, placed []*v1.Silo, env Env) (Movability, error) {
	if env.Hosts == nil {
		env.Hosts = hosts
	}
	m := Movability{Host: silo.Status.Host, Excluded: map[string]string{}}
	ls, wait := addressLimits(silo, env)
	if wait != "" {
		m.Wait = wait
		return m, nil
	}
	m.Area = intersect(ls, env.Hosts)
	if m.Area.Conflict != "" {
		return m, nil
	}
	// The silo keeps its status.host: a balancer that exists reaches it within its scope there.
	for _, h := range hosts {
		if h.Name == silo.Status.Host || h.Spec.Components.Worker == nil || excludedBy(ls, h) != "" {
			continue // outside the area: the area says why
		}
		d, err := ScheduleIn(silo, []*v1.Host{h}, placed, env)
		if err != nil {
			return m, err
		}
		switch {
		case d.Host == h.Name:
			m.To = append(m.To, h.Name)
		case d.Excluded[h.Name] != "":
			m.Excluded[h.Name] = d.Excluded[h.Name]
		default:
			m.Excluded[h.Name] = d.Message()
		}
	}
	sort.Strings(m.To)
	return m, nil
}

// String is the line for people:
//
//	can move: to hv2, hv3 (anywhere: its ways in follow the worker)
//	can move: to lin-2 (within linode machines in us-ord: IP api-edge is linode's, in us-ord)
//	can move: no (pinned to host bm-1: IP mail is host bm-1's address)
//	can move: no other host fits now (within region us-ord: …; lin-2: not enough memory (needs 8Gi))
//	can move: not now (IP api-edge is held by silo/old: …)
//	can move: nowhere (IP a is host h1's address, and IP b is host h2's address: no host has both)
func (m Movability) String() string {
	switch {
	case m.Wait != "":
		return "can move: not now (" + m.Wait + ")"
	case m.Area.Conflict != "":
		return "can move: nowhere (" + m.Area.Conflict + ")"
	case m.Area.Host != "" && (m.Area.Host == m.Host || m.Host == ""):
		return "can move: no (pinned to host " + m.Area.Host + ": " + m.because() + ")"
	}
	within := "within " + m.Area.String() + ": " + m.because()
	if m.Area.Anywhere() {
		within = "anywhere: its ways in follow the worker"
	}
	if len(m.To) > 0 {
		return "can move: to " + strings.Join(m.To, ", ") + " (" + within + ")"
	}
	out := "can move: no other host fits now (" + within
	names := make([]string, 0, len(m.Excluded))
	for h := range m.Excluded {
		names = append(names, h)
	}
	sort.Strings(names)
	for _, h := range names {
		out += "; " + h + ": " + m.Excluded[h]
	}
	return out + ")"
}

func (m Movability) because() string {
	if len(m.Area.Because) == 0 {
		return "its ways in follow the worker"
	}
	return strings.Join(m.Area.Because, "; ")
}

// MoveTo is why a move of silo to host to is refused ("" when it's allowed), by the same rules
// as placement: out of its ways in's reach, or any other rule to fails. The move path asks this.
func MoveTo(silo *v1.Silo, to *v1.Host, hosts []*v1.Host, placed []*v1.Silo, env Env) (string, error) {
	if env.Hosts == nil {
		env.Hosts = hosts
	}
	d, err := ScheduleIn(silo, []*v1.Host{to}, placed, env) // its status.host kept: see CanMove
	if err != nil || d.Host == to.Name {
		return "", err
	}
	if why := d.Excluded[to.Name]; why != "" {
		return why, nil
	}
	return d.Message(), nil
}

// Movable is the silo's status.movable for networking v2: yes or no, and why, from where its
// ways in let it be and where its data can go (data: the storage's own summary, moves.Summary:
// Anywhere, Region (R), Region, Recreate, Pinned (HOST), Pinned). It doesn't depend on room on
// other hosts right now (that's CanMove's), so it changes only when the silo or its addresses do.
// kvo describe silo prints it as is:
//
//	yes: any worker
//	yes: within linode/us-ord (IP api-edge)
//	no: pinned to baremetal-1 (IP mail is that host's address)
//	no: pinned to hv1 (its disks stay there)
//	not now: IP mail is held by silo/old: …
func Movable(s *v1.Silo, env Env, data string) string {
	a, wait := AreaOf(s, env)
	switch {
	case wait != "":
		return "not now: " + wait
	case a.Conflict != "":
		return "no: " + a.Conflict
	}
	fresh := ""
	switch {
	case strings.HasPrefix(data, "Pinned"):
		h := strings.TrimSuffix(strings.TrimPrefix(data, "Pinned ("), ")")
		if h == data || h == "" {
			h = s.Status.Host
		}
		if a.Host != "" && a.Host != h && h != "" {
			return "no: its disks stay on " + h + ", and " + a.PinnedBy + " (" + a.Host + ")"
		}
		if h == "" {
			return "no: pinned to the host it's placed on (its disks stay there)"
		}
		return "no: pinned to " + h + " (its disks stay there)"
	case data == "Recreate":
		fresh = ", without its data (onHostLoss: Recreate)"
	case strings.HasPrefix(data, "Region (") && a.Host == "":
		r := strings.TrimSuffix(strings.TrimPrefix(data, "Region ("), ")")
		if a.Regions != nil && !slices.Contains(a.Regions, r) {
			return "no: its volumes are in " + r + ", and " + strings.Join(a.Subjects, ", ") + " in " + strings.Join(a.Regions, ", ")
		}
		a.Regions = []string{r}
		a.Subjects = append(a.Subjects, "its volumes")
	}
	if a.Host != "" {
		return "no: pinned to " + a.Host + " (" + a.PinnedBy + ")"
	}
	if a.Provider == "" && a.Regions == nil {
		return "yes: any worker" + fresh
	}
	var where string
	switch {
	case a.Provider != "" && a.Regions != nil:
		var each []string
		for _, r := range a.Regions {
			each = append(each, a.Provider+"/"+r)
		}
		where = strings.Join(each, " or ")
	case a.Provider != "":
		where = a.Provider + " machines"
	default:
		where = "region " + strings.Join(a.Regions, " or ")
	}
	return "yes: within " + where + " (" + strings.Join(a.Subjects, ", ") + ")" + fresh
}
