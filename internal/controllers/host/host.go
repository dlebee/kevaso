// Package host is the control plane's host-lease controller: a host whose kevasod stops reporting
// is marked lost (Ready Unknown, reason HostLost) once its lease runs out, which is what the silo
// controller's onHostLoss policies act on.
package host

import (
	"context"
	"fmt"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
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
