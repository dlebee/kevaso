package ip

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/ips"
)

// FinalizerIPSet holds an IPSet until the IPs it made are deleted (their own finalizer releases
// each address).
const FinalizerIPSet = "kevaso.com/ipset"

// Sets reconciles IPSets (networking v2): one member per SiloSet instance, by ordinal. Members
// are ordinary IP objects; the IP controller binds each to its instance (own) like any IP.
//   - Static: a member { ip: NAME } is that IP, as it is; a member { hostAddress: NAME } is an IP
//     of type Host the set makes, SET-i. Members only grow at the end (admission), never renumbered.
//   - Dynamic: SET-i of type Provider, made as the SiloSets naming the set need them, up to max,
//     and kept per ordinal when they scale in (the same instance gets the same address back).
//
// Deleting the set deletes the IPs it made (refused, and retried, while an instance holds one).
// An instance past the set's last member waits: the set's Short condition says so, and the
// scheduler tells the instance.
type Sets struct {
	Client   *client.Client
	IPSets   *informer.Informer
	IPs      *informer.Informer
	Silos    *informer.Informer
	SiloSets *informer.Informer
	// Hosts give a Static set's hostAddress member its family (its address's): the member's IP is
	// made once a host has the address. nil: made at once, IPv4.
	Hosts *informer.Informer
	Clock clock.Clock
}

// Name implements engine.Controller.
func (c *Sets) Name() string { return "ipsets" }

// Kind implements engine.Controller.
func (c *Sets) Kind() string { return "IPSet" }

func (c *Sets) now() time.Time {
	if c.Clock == nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return c.Clock.Now().UTC().Truncate(time.Second)
}

// Reconcile implements engine.Controller.
func (c *Sets) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	if !informer.AllSynced(c.IPSets, c.IPs, c.Silos, c.SiloSets) || (c.Hosts != nil && !informer.AllSynced(c.Hosts)) {
		return engine.Result{RequeueAfter: time.Second}, nil
	}
	o, ok := c.IPSets.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	set := o.(*v1.IPSet)
	if set.DeletionTimestamp != nil {
		return c.remove(ctx, set)
	}
	if !slices.Contains(set.Finalizers, FinalizerIPSet) {
		set.Finalizers = append(set.Finalizers, FinalizerIPSet)
		return engine.Result{}, c.Client.Update(ctx, set)
	}

	var siloSets []*v1.SiloSet
	for _, o := range c.SiloSets.List() {
		siloSets = append(siloSets, o.(*v1.SiloSet))
	}
	using, want := ips.SiloSetsUsing(set, siloSets)
	for _, ss := range using { // an instance past the spec (scaling in, a surge) still needs its member
		for _, so := range c.Silos.List() {
			if s := o2silo(so); s.Namespace == set.Namespace {
				if name, i := ips.InstanceOf(s); name == ss.Name && i+1 > want {
					want = i + 1
				}
			}
		}
	}
	made := c.made(set)
	n := ips.Size(set)
	if set.Spec.Type == v1.IPSetDynamic {
		n = min(max(want, highest(made)+1), set.Spec.Max) // reserved as needed, kept once made
	}

	var problems []string
	for i := range n {
		family := set.Spec.Family
		if set.Spec.Type == v1.IPSetStatic && set.Spec.Members[i].HostAddress != "" && c.Hosts != nil {
			a := set.Spec.Members[i].HostAddress
			_, ha, ok := ips.FindAddress(c.hosts(), a)
			if !ok {
				problems = append(problems, fmt.Sprintf("member %d: no host has address %s yet (kvoadm host addresses HOST add %s ADDRESS): its IP is made, of that address's family, once one does", i, a, a))
				continue
			}
			family = ha.Family()
		}
		want := ips.Made(set, i, family)
		if want == nil {
			continue
		}
		if cur, ok := c.IPs.Get(set.Namespace, want.Name); ok {
			if !ips.MadeBy(cur.(*v1.IP), set.Name, i) {
				problems = append(problems, fmt.Sprintf("IP %s exists and isn't member %d of the set (it has no %s=%s label): rename or delete it", want.Name, i, v1.LabelIPSet, set.Name))
			}
			continue
		}
		err := c.Client.Create(ctx, want)
		if client.IsAlreadyExists(err) {
			return engine.Result{RequeueAfter: time.Second}, nil // the cache catches up
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("making IP %s: %v", want.Name, err))
		}
	}

	if c.Hosts != nil { // one family per set: a member made or added since admission may differ
		var nsIPs []*v1.IP
		for _, o := range c.IPs.List() {
			if x := o.(*v1.IP); x.Namespace == set.Namespace {
				nsIPs = append(nsIPs, x)
			}
		}
		if why := ips.SetFamilies(set, nsIPs, c.hosts()); why != "" {
			problems = append([]string{why}, problems...)
		}
	}

	st := v1.IPSetStatus{Conditions: slices.Clone(set.Status.Conditions)}
	used := 0
	for i := range n {
		name, _ := ips.MemberIP(set, i)
		m := v1.IPSetMemberStatus{Ordinal: i, IP: name}
		if xo, ok := c.IPs.Get(set.Namespace, name); ok {
			x := xo.(*v1.IP)
			m.Address = x.Status.Address
			if h := x.Status.Holder; h != nil {
				m.UsedBy = h.Holder
				used++
			}
		}
		st.Members = append(st.Members, m)
	}
	ready := meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "Ready",
		Message: fmt.Sprintf("%d member(s), %d in use", len(st.Members), used), ObservedGeneration: set.Generation}
	if len(problems) > 0 {
		ready.Status, ready.Reason, ready.Message = meta.ConditionFalse, "MemberConflict", problems[0]
	}
	meta.SetCondition(&st.Conditions, ready, c.now())
	short := meta.Condition{Type: "Short", Status: meta.ConditionFalse, Reason: "Enough", Message: "every instance has a member", ObservedGeneration: set.Generation}
	if size := ips.Size(set); want > size {
		short.Status, short.Reason = meta.ConditionTrue, "Short"
		short.Message = fmt.Sprintf("instances need %d member(s) and the set has %d: instances from %d on wait", want, size, size)
		if set.Spec.Type == v1.IPSetDynamic {
			short.Message += " (raise max)"
		} else {
			short.Message += " (add members at the end)"
		}
	}
	meta.SetCondition(&st.Conditions, short, c.now())
	if !setStatusEqual(set.Status, st) {
		set.Status = st
		if err := c.Client.UpdateStatus(ctx, set); err != nil {
			return engine.Result{}, err
		}
	}
	if len(problems) > 0 {
		return engine.Result{RequeueAfter: 30 * time.Second}, nil
	}
	return engine.Result{}, nil
}

func o2silo(o meta.Object) *v1.Silo { return o.(*v1.Silo) }

func (c *Sets) hosts() []*v1.Host {
	var out []*v1.Host
	for _, o := range c.Hosts.List() {
		out = append(out, o.(*v1.Host))
	}
	return out
}

// made are the IPs the set made, by ordinal.
func (c *Sets) made(set *v1.IPSet) map[int]*v1.IP {
	out := map[int]*v1.IP{}
	for _, o := range c.IPs.List() {
		x := o.(*v1.IP)
		if x.Namespace != set.Namespace || x.Labels[v1.LabelIPSet] != set.Name {
			continue
		}
		if i, err := strconv.Atoi(x.Labels[v1.LabelIPSetOrdinal]); err == nil && i >= 0 {
			out[i] = x
		}
	}
	return out
}

func highest(m map[int]*v1.IP) int {
	h := -1
	for i := range m {
		h = max(h, i)
	}
	return h
}

// remove deletes the IPs the set made, then lets the set go. A member an instance still holds
// is refused (409) and tried again: the namespace cascade stops the silos first.
func (c *Sets) remove(ctx context.Context, set *v1.IPSet) (engine.Result, error) {
	if !slices.Contains(set.Finalizers, FinalizerIPSet) {
		return engine.Result{}, nil
	}
	made := c.made(set)
	if len(made) > 0 {
		var held []string
		for _, x := range made {
			if x.DeletionTimestamp != nil {
				continue
			}
			err := c.Client.Delete(ctx, "IP", x.Namespace, x.Name)
			switch {
			case client.IsConflict(err):
				held = append(held, x.Name+" ("+x.Status.Holders()+")")
			case err != nil && !client.IsNotFound(err):
				return engine.Result{}, fmt.Errorf("delete member IP %s: %w", x.Name, err)
			}
		}
		msg := fmt.Sprintf("deleting %d member IP(s)", len(made))
		if len(held) > 0 {
			slices.Sort(held)
			msg = fmt.Sprintf("member IPs still held: %v; they go once their instances do", held)
		}
		if meta.SetCondition(&set.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "Deleting", Message: msg, ObservedGeneration: set.Generation}, c.now()) {
			_ = client.IgnoreNotFound(c.Client.UpdateStatus(ctx, set))
		}
		return engine.Result{RequeueAfter: 2 * time.Second}, nil
	}
	set.Finalizers = slices.DeleteFunc(set.Finalizers, func(f string) bool { return f == FinalizerIPSet })
	return engine.Result{}, client.IgnoreNotFound(c.Client.Update(ctx, set))
}

func setStatusEqual(a, b v1.IPSetStatus) bool {
	if !slices.Equal(a.Members, b.Members) || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for i := range a.Conditions {
		x, y := a.Conditions[i], b.Conditions[i]
		if x.Type != y.Type || x.Status != y.Status || x.Reason != y.Reason || x.Message != y.Message || x.ObservedGeneration != y.ObservedGeneration {
			return false
		}
	}
	return true
}

// Map implements engine.Mapper: an IP of the set (made by it, or a Static member), a SiloSet
// naming it, and an instance of such a SiloSet reach the set.
func (c *Sets) Map(changed engine.Key) []engine.Key {
	var keys []engine.Key
	add := func(ns, name string) {
		if name != "" && !slices.ContainsFunc(keys, func(k engine.Key) bool { return k.Namespace == ns && k.Name == name }) {
			keys = append(keys, engine.Key{Kind: "IPSet", Namespace: ns, Name: name})
		}
	}
	switch changed.Kind {
	case "Host": // a host address a Static set's member waits for (its IP not made yet)
		for _, o := range c.IPSets.List() {
			set := o.(*v1.IPSet)
			if set.Spec.Type != v1.IPSetStatic {
				continue
			}
			for i, m := range set.Spec.Members {
				name, _ := ips.MemberIP(set, i)
				if _, made := c.IPs.Get(set.Namespace, name); m.HostAddress != "" && !made {
					add(set.Namespace, set.Name)
					break
				}
			}
		}
	case "IP":
		if o, ok := c.IPs.Get(changed.Namespace, changed.Name); ok {
			add(changed.Namespace, o.(*v1.IP).Labels[v1.LabelIPSet])
		}
		for _, o := range c.IPSets.List() {
			set := o.(*v1.IPSet)
			if set.Namespace == changed.Namespace && slices.ContainsFunc(set.Spec.Members, func(m v1.IPSetMember) bool { return m.IP == changed.Name }) {
				add(set.Namespace, set.Name)
			}
		}
		if len(keys) == 0 { // a made IP deleted: its set by its name (SET-i)
			for _, o := range c.IPSets.List() {
				set := o.(*v1.IPSet)
				if set.Namespace == changed.Namespace && v1.InstanceIndex(set.Name, changed.Name) >= 0 {
					add(set.Namespace, set.Name)
				}
			}
		}
	case "SiloSet":
		if o, ok := c.SiloSets.Get(changed.Namespace, changed.Name); ok {
			add(changed.Namespace, o.(*v1.SiloSet).Spec.IPs)
		}
		for _, o := range c.IPSets.List() { // or one that named it before
			if set := o.(*v1.IPSet); set.Namespace == changed.Namespace && set.Spec.Type == v1.IPSetDynamic {
				add(set.Namespace, set.Name)
			}
		}
	case "Silo":
		if o, ok := c.Silos.Get(changed.Namespace, changed.Name); ok {
			if set, _ := ips.InstanceOf(o.(*v1.Silo)); set != "" {
				if so, ok := c.SiloSets.Get(changed.Namespace, set); ok {
					add(changed.Namespace, so.(*v1.SiloSet).Spec.IPs)
				}
			}
		}
	}
	return keys
}

var (
	_ engine.Controller = (*Sets)(nil)
	_ engine.Mapper     = (*Sets)(nil)
)
