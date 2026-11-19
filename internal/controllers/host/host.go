// Package host is the control plane's host controller. It gives every host its place on the mesh
// (an index, its mesh IP and silo subnet), and runs the host lease: a host whose kevasod stops
// reporting is marked lost (Ready Unknown, reason HostLost) once its lease runs out. That only
// informs: the silo controller marks the host's silos HostUnreachable and starts no other copy
// (brainstorm §0.7); a person's kvo move … --confirm-fenced moves them.
package host

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/claims"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/mesh"
)

// DefaultLease is how long a host may go without a heartbeat before it's lost. Agents fence
// (stop silos that may be recreated elsewhere) earlier than this; see agent.FenceAfter.
const DefaultLease = 40 * time.Second

// ReasonLost marks a host whose lease ran out.
const ReasonLost = "HostLost"

// Decide returns the host's Ready condition given its last heartbeat, whether it changes, and when
// to look again. Pure.
func Decide(h *v1.Host, now time.Time, lease time.Duration) (meta.Condition, bool, time.Duration) {
	cur := meta.FindCondition(h.Status.Conditions, "Ready")
	if h.Status.LastHeartbeat == nil {
		return meta.Condition{}, false, lease // never reported: nothing to expire yet
	}
	age := now.Sub(*h.Status.LastHeartbeat)
	if age < lease {
		return meta.Condition{}, false, lease - age
	}
	if cur != nil && cur.Status == meta.ConditionUnknown && cur.Reason == ReasonLost {
		return meta.Condition{}, false, lease // already lost
	}
	return meta.Condition{Type: "Ready", Status: meta.ConditionUnknown, Reason: ReasonLost,
		Message: fmt.Sprintf("no heartbeat for %s", age.Round(time.Second)), ObservedGeneration: h.Generation}, true, lease
}

// Lost reports whether a host is lost, and since when.
func Lost(h *v1.Host) (bool, time.Time) {
	c := meta.FindCondition(h.Status.Conditions, "Ready")
	if c != nil && c.Status == meta.ConditionUnknown && c.Reason == ReasonLost {
		return true, c.LastTransitionTime
	}
	return false, time.Time{}
}

// Controller applies Decide to every host.
type Controller struct {
	Client *client.Client
	Hosts  *informer.Informer
	Clock  clock.Clock
	Lease  time.Duration

	mu       sync.Mutex
	assigned map[string]int // indexes written but maybe not in the cache yet (like an assume cache)
	// Claims make each mesh index one host's, by the store (another leader's writes included).
	Claims *claims.Claims
	// Contacts, if set, learn of every heartbeat seen (the silo controller reads them).
	Contacts *Contacts
}

// PoolMeshIndex is the claims pool of hosts' mesh indexes.
const PoolMeshIndex = "mesh-index"

// UsesMeshIndex says whether a stored Host still has the mesh index.
func UsesMeshIndex(obj []byte, value string) bool {
	var h v1.Host
	return json.Unmarshal(obj, &h) == nil && strconv.Itoa(h.Status.Network.Index) == value
}

// assignIndex gives h its mesh index if it has none, reporting whether it wrote. Called with c.mu
// held.
func (c *Controller) assignIndex(ctx context.Context, h *v1.Host) (bool, error) {
	if n := &h.Status.Network; n.Index > 0 {
		delete(c.assigned, h.Name)
		// The addresses follow from the index (mesh.Addresses): one rewritten in the Host's status
		// is put back, so it is never what peers keep (review of the control-plane fixes, item 2).
		meshIP, subnet, inner := mesh.Addresses(n.Index)
		if n.MeshIP == meshIP && n.SiloSubnet == subnet && n.InnerIP == inner {
			return false, nil
		}
		n.MeshIP, n.SiloSubnet, n.InnerIP = meshIP, subnet, inner
		return true, c.Client.UpdateStatus(ctx, h)
	}
	if c.assigned == nil {
		c.assigned = map[string]int{}
	}
	var hosts []*v1.Host
	for _, o := range c.Hosts.List() {
		x := o.(*v1.Host)
		if i, ok := c.assigned[x.Name]; ok && x.Status.Network.Index == 0 && x.Name != h.Name {
			x.Status.Network.Index = i
		}
		hosts = append(hosts, x)
	}
	var i int
	for {
		got, err := mesh.AssignIndexes(hosts)
		if err != nil {
			return false, err
		}
		var ok bool
		if i, ok = got[h.Name]; !ok {
			return false, nil
		}
		if c.Claims == nil {
			break
		}
		ok, _, err = c.Claims.Take(ctx, PoolMeshIndex, strconv.Itoa(i), claims.Holder{Kind: "Host", Name: h.Name, UID: h.UID, Version: h.ResourceVersion}, UsesMeshIndex)
		if err != nil {
			return false, err
		}
		if ok {
			break
		}
		// Another host has it (the cache doesn't show it yet): the next one.
		taken := &v1.Host{}
		taken.Status.Network.Index = i
		hosts = append(hosts, taken)
	}
	n := &h.Status.Network
	n.Index = i
	n.MeshIP, n.SiloSubnet, n.InnerIP = mesh.Addresses(i)
	if err := c.Client.UpdateStatus(ctx, h); err != nil {
		return false, err
	}
	c.assigned[h.Name] = i
	return true, nil
}

// Name implements engine.Controller.
func (c *Controller) Name() string { return "host-lease" }

// Kind implements engine.Controller.
func (c *Controller) Kind() string { return "Host" }

// Reconcile implements engine.Controller.
func (c *Controller) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.Hosts.Get("", k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	h := o.(*v1.Host)
	c.Contacts.Observe(h, c.Clock.Now())
	c.mu.Lock()
	wrote, err := c.assignIndex(ctx, h)
	c.mu.Unlock()
	if err != nil {
		return engine.Result{}, err
	}
	if wrote {
		return engine.Result{RequeueAfter: 10 * time.Millisecond}, nil // continue from fresh state
	}
	lease := c.Lease
	if lease <= 0 {
		lease = DefaultLease
	}
	now := c.Clock.Now().UTC()
	cond, changed, again := Decide(h, now, lease)
	if changed {
		meta.SetCondition(&h.Status.Conditions, cond, now.Truncate(time.Second))
		if err := c.Client.UpdateStatus(ctx, h); err != nil {
			return engine.Result{}, err // a heartbeat raced us: look again with fresh state
		}
	}
	return engine.Result{RequeueAfter: again + time.Second}, nil
}

var _ engine.Controller = (*Controller)(nil)
