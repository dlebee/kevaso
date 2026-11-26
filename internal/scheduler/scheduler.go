// Package scheduler places silos on hosts (design §3.3): the cluster chooses, workers offer and can
// repel with taints, silos pick. Schedule is a pure function: hosts and existing silos in, one host
// (or the reason for each host it couldn't use) out.
//
// In order, a host must:
//  1. have the worker component, and be Ready;
//  2. have the silo's runtime installed and Ready;
//  3. carry every label in the silo's hostSelector;
//  4. have no NoSchedule taint the silo doesn't tolerate;
//  5. have room: allocatable CPU and memory minus what silos already placed there ask for;
//  6. for its worker host ports: the address (internal or external) with the numbers free;
//  7. be where its addresses can be (address.go: placement follows the address): a Host IP's
//     host, a Provider IP's or a balancer's provider reach, an IPSet member's by its type, all
//     of them at once;
//  8. for a plugin's storage class: be one of that plugin's machines, in the region the silo's
//     volumes already are.
//
// Some reasons hold for every host and clear by themselves (an IP not held yet, no free IPSet
// member, a Provider IP without its address yet, no worker with the address a host port asks
// for): the decision then carries that one Reason.
//
// Among the hosts left, it prefers ones without an untolerated PreferNoSchedule taint, then (for a
// silo with placement.spread, like a SiloSet's instances) the host whose domain has the fewest of
// the silos it spreads from, then the one with the most free memory (spreading silos out), then the name (so it's deterministic).
package scheduler

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Decision is where a silo goes, or why it can't go anywhere yet.
type Decision struct {
	Host     string            // empty: nowhere fits
	Excluded map[string]string // host → the first rule it failed
	// Reason: why no host can take it, the same for all of them (it goes ahead by itself once
	// that changes).
	Reason string
}

// Message summarises an unschedulable decision for the silo's condition.
func (d Decision) Message() string {
	if d.Host != "" {
		return "scheduled on " + d.Host
	}
	if d.Reason != "" {
		return d.Reason
	}
	if len(d.Excluded) == 0 {
		return "no hosts with a worker component"
	}
	names := make([]string, 0, len(d.Excluded))
	for h := range d.Excluded {
		names = append(names, h)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, h := range names {
		parts = append(parts, h+": "+d.Excluded[h])
	}
	return "no host fits (" + strings.Join(parts, "; ") + ")"
}

type usage struct {
	cpu int
	mem int64
}

// Class is what the scheduler needs about a plugin's class.
type Class struct {
	Plugin       string // the plugin serving it
	OwnHostsOnly bool   // only the plugin's own machines can use it
	NodePorts    bool   // load balancers: the host gets node ports
	Reserve      bool   // load balancers: it holds an address apart from a load balancer
	Follows      string // load balancers: where an address goes with its silo (host | region | global)
	SendsFrom    bool   // load balancers: the address is on the silo's host, so it can send from it
	Exclusive    bool   // load balancers: one host has the address at a time: never shared
	Topology     string // storage: host (default) | zone | region | global
	Mount        bool   // storage: the plugin's node side mounts it, so only hosts running that can take it
}

// Env is the rest of the cluster a decision depends on.
type Env struct {
	// IPs are the IP objects; Hosts every host, for their named extra addresses (default: the
	// hosts scheduled onto).
	IPs   []*v1.IP
	Hosts []*v1.Host
	// Classes are the plugins' load-balancer and storage classes, by name.
	Classes map[string]Class
	// Images are the VMImage objects, for resolving silos' vm.image.
	Images []*v1.VMImage
	// Suffix is the cluster's names' last label ("": kevaso).
	Suffix string
	// Claimed are, by host, values the store says other silos hold there, which the cache may
	// not show yet (K-029): such a node port isn't handed out, and a host where a host port the
	// silo asks for is held isn't a fit.
	Claimed map[string]Claimed
	// Silence is how long the control plane itself has heard nothing from a host, on its own
	// clock (controllers/host.Contacts; K-014). Nil: unknown, never long enough to act on.
	Silence func(host string) time.Duration
	// StartClaimAge is how long ago the control plane itself first saw the start claim the silo
	// carries now (controllers/host.Contacts; K-015), on its own clock: 0 for one not seen yet.
	// Nil: unknown, so a start claim of the silo's host always stands.
	StartClaimAge func(s *v1.Silo) time.Duration
	// Restore is the open restored history, when there is one. An unsettled silo is not placed.
	Restore *v1.RestoreGate
	// Networking says where each provider's IPs and balancers reach (plugins.Registry). Nil: only
	// the provider's own machines, in the region.
	Networking Reacher
	// IPSets and SiloSets are for own (a SiloSet instance's IPSet member, by ordinal).
	IPSets   []*v1.IPSet
	SiloSets []*v1.SiloSet
}

// Claimed are values held on one host.
type Claimed struct {
	NodePorts map[int]bool
	HostPorts map[HostPort]bool
}

// Schedule picks a host for silo. placed are all silos already assigned (status.host set); ips,
// the IP objects (for silos whose addresses are IPs).
func Schedule(silo *v1.Silo, hosts []*v1.Host, placed []*v1.Silo, ips ...*v1.IP) (Decision, error) {
	return ScheduleIn(silo, hosts, placed, Env{IPs: ips})
}

// ScheduleIn is Schedule with plugins' classes.
func ScheduleIn(silo *v1.Silo, hosts []*v1.Host, placed []*v1.Silo, env Env) (Decision, error) {
	if env.Hosts == nil {
		env.Hosts = hosts
	}
	needMem, err := v1.ParseBytes(silo.Spec.Resources.Memory)
	if err != nil {
		return Decision{}, err
	}
	used := map[string]usage{}
	runtimeCount := map[string]int{} // host\x00runtime → silos placed there
	for _, s := range placed {
		if s.Status.Host == "" || (s.Namespace == silo.Namespace && s.Name == silo.Name) {
			continue
		}
		m, err := v1.ParseBytes(s.Spec.Resources.Memory)
		if err != nil {
			continue // already admitted; a bad value can't happen, and must not block scheduling
		}
		runtimeCount[s.Status.Host+"\x00"+s.Spec.Runtime]++
		u := used[s.Status.Host]
		u.cpu += s.Spec.Resources.CPU
		u.mem += m
		used[s.Status.Host] = u
	}

	type candidate struct {
		name     string
		prefer   bool // no untolerated PreferNoSchedule taint
		siblings int  // silos it's spread from already in the host's domain
		freeMem  int64
	}
	spread := spreadCounts(silo, hosts, placed)
	d := Decision{Excluded: map[string]string{}}
	limits, wait := addressLimits(silo, env)
	if wait != "" {
		d.Reason = wait
		return d, nil
	}
	if a := intersect(limits, env.Hosts); a.Conflict != "" {
		d.Reason = "its ways in can't meet: " + a.Conflict
		return d, nil
	}
	var noAddress []HostPort // per host the address it lacks, when that was the only reason
	var fits []candidate
	for _, h := range hosts {
		w := h.Spec.Components.Worker
		if w == nil {
			continue // not a worker: not even a candidate
		}
		reason := filter(silo, h, w, used[h.Name], needMem, runtimeCount[h.Name+"\x00"+silo.Spec.Runtime])
		if reason == "" {
			reason = netFilter(silo, h, placed, env)
			if w, ok := missingAddress(silo, h); ok && reason != "" {
				noAddress = append(noAddress, w)
			}
		}
		if reason == "" {
			reason = excludedBy(limits, h)
		}
		if reason == "" {
			reason = classFilter(silo, h, env.Classes)
		}
		if reason != "" {
			d.Excluded[h.Name] = reason
			continue
		}
		allocMem, _ := v1.ParseBytes(h.Status.Allocatable.Memory)
		fits = append(fits, candidate{
			name:     h.Name,
			prefer:   !untoleratedTaint(silo, w.Taints, v1.PreferNoSchedule),
			siblings: spread(h),
			freeMem:  allocMem - used[h.Name].mem - needMem,
		})
	}
	if len(fits) == 0 {
		d.Reason = noWorkerWith(silo, noAddress, len(d.Excluded))
		return d, nil
	}
	sort.Slice(fits, func(i, j int) bool {
		a, b := fits[i], fits[j]
		if a.prefer != b.prefer {
			return a.prefer
		}
		if a.siblings != b.siblings {
			return a.siblings < b.siblings
		}
		if a.freeMem != b.freeMem {
			return a.freeMem > b.freeMem
		}
		return a.name < b.name
	})
	d.Host = fits[0].name
	return d, nil
}

func filter(silo *v1.Silo, h *v1.Host, w *v1.WorkerSpec, u usage, needMem int64, ofRuntime int) string {
	if !meta.IsTrue(h.Status.Conditions, "Ready") {
		return "host not Ready"
	}
	if rs, ok := h.Status.Runtimes[silo.Spec.Runtime]; !ok || rs.State != "Ready" {
		installed := false
		for _, r := range w.Runtimes {
			installed = installed || r.Name == silo.Spec.Runtime
		}
		if !installed {
			return "runtime " + silo.Spec.Runtime + " not installed"
		}
		return "runtime " + silo.Spec.Runtime + " not Ready"
	}
	if h.Spec.Unschedulable {
		return "host is cordoned (draining)"
	}
	if max := h.Status.Runtimes[silo.Spec.Runtime].MaxSilos; max > 0 && ofRuntime >= max {
		return fmt.Sprintf("runtime %s runs at most %d silos on a host (%d placed here)", silo.Spec.Runtime, max, ofRuntime)
	}
	if r := silo.Spec.Placement.Region; r != "" && h.Spec.Region != r {
		return fmt.Sprintf("in region %s, not %s", dashed(h.Spec.Region), r)
	}
	if z := silo.Spec.Placement.Zone; z != "" && h.Spec.Zone != z {
		return fmt.Sprintf("in zone %s, not %s", dashed(h.Spec.Zone), z)
	}
	for k, want := range silo.Spec.Placement.HostSelector {
		if got, ok := w.Labels[k]; !ok || got != want {
			return fmt.Sprintf("label %s=%s missing", k, want)
		}
	}
	if untoleratedTaint(silo, w.Taints, v1.NoSchedule) {
		return "taint not tolerated"
	}
	allocMem, err := v1.ParseBytes(h.Status.Allocatable.Memory)
	if err != nil {
		return "allocatable memory unreadable"
	}
	if h.Status.Allocatable.CPU > 0 && u.cpu+silo.Spec.Resources.CPU > h.Status.Allocatable.CPU {
		return fmt.Sprintf("not enough CPU (%d of %d in use, needs %d)", u.cpu, h.Status.Allocatable.CPU, silo.Spec.Resources.CPU)
	}
	if allocMem > 0 && u.mem+needMem > allocMem {
		return fmt.Sprintf("not enough memory (needs %s)", silo.Spec.Resources.Memory)
	}
	return ""
}

// noWorkerWith is the reason when every one of the excluded hosts lacked the address a host port
// asks for (the same one), "" otherwise: no worker has it, and the silo waits for one that does.
func noWorkerWith(silo *v1.Silo, missing []HostPort, excluded int) string {
	if excluded == 0 || len(missing) != excluded {
		return ""
	}
	w := missing[0]
	for _, m := range missing {
		if m.Network != w.Network {
			return ""
		}
	}
	what := "worker"
	if silo.Spec.Runtime == v1.RuntimeTart {
		what = "Mac"
		if w.Network == v1.NetworkExternal {
			return fmt.Sprintf("no Mac with a public IP, which port %d/%s asks for (hostPort: worker external): it goes ahead once one has one", w.Port, w.Proto)
		}
	}
	return fmt.Sprintf("no %s with an %s IP, which port %d/%s asks for (hostPort: worker %s): it goes ahead once one has one", what, w.Network, w.Port, w.Proto, w.Network)
}

// classFilter: a plugin's class needs one of the plugin's machines, and volumes that already exist
// keep the silo in their region.
func classFilter(silo *v1.Silo, h *v1.Host, classes map[string]Class) string {
	var used []string
	for _, v := range v1.PluginVolumes(silo) {
		used = append(used, v.Class)
	}
	for _, name := range used {
		c, ok := classes[name]
		if !ok {
			return "class " + name + ": no plugin serves it (is its plugin installed and running?)"
		}
		if c.OwnHostsOnly && (h.Status.Provider == nil || h.Status.Provider.Name != c.Plugin) {
			return "class " + name + " needs a " + c.Plugin + " machine"
		}
		if c.Mount && !slices.Contains(h.Status.MountClasses, name) {
			return "class " + name + " needs the " + c.Plugin + " plugin's node side on the host"
		}
	}
	for _, v := range silo.Status.Volumes {
		if v.Region != "" && (h.Status.Provider == nil || h.Status.Provider.Region != v.Region) {
			return fmt.Sprintf("volume %s is in region %s", v.Name, v.Region)
		}
	}
	return ""
}

// spreadCounts returns, per host, how many of the silos the silo is spread from (placement.spread:
// same namespace, selected by its labels) are already in that host's domain (the host, its zone or
// its region).
func spreadCounts(silo *v1.Silo, hosts []*v1.Host, placed []*v1.Silo) func(*v1.Host) int {
	sp := silo.Spec.Placement.Spread
	if sp == nil {
		return func(*v1.Host) int { return 0 }
	}
	domain := func(h *v1.Host) string {
		switch sp.By {
		case "zone":
			return h.Spec.Region + "/" + h.Spec.Zone
		case "region":
			return h.Spec.Region
		}
		return h.Name
	}
	byName := map[string]*v1.Host{}
	for _, h := range hosts {
		byName[h.Name] = h
	}
	counts := map[string]int{}
	for _, s := range placed {
		if s.Namespace != silo.Namespace || s.Name == silo.Name || s.Status.Host == "" || s.DeletionTimestamp != nil || !v1.Selects(sp.Selector, s.Labels) {
			continue
		}
		if h, ok := byName[s.Status.Host]; ok {
			counts[domain(h)]++
		}
	}
	return func(h *v1.Host) int { return counts[domain(h)] }
}

func untoleratedTaint(silo *v1.Silo, taints []v1.Taint, effect v1.TaintEffect) bool {
	for _, t := range taints {
		if t.Effect != effect {
			continue
		}
		tolerated := false
		for _, tol := range silo.Spec.Tolerations {
			if tol.Tolerates(t) {
				tolerated = true
				break
			}
		}
		if !tolerated {
			return true
		}
	}
	return false
}

func dashed(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
