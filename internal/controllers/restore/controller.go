package restore

import (
	"context"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/engine"
)

// Controller writes each silo's restore mark from the hosts' inventories.
type Controller struct {
	Client *client.Client
	Silos  *informer.Informer
	Hosts  *informer.Informer
	Gates  *informer.Informer
}

// Name implements engine.Controller.
func (c *Controller) Name() string { return "restore" }

// Kind implements engine.Controller.
func (c *Controller) Kind() string { return "Silo" }

// Reconcile implements engine.Controller.
func (c *Controller) Reconcile(ctx context.Context, key engine.Key) (engine.Result, error) {
	var s v1.Silo
	if err := c.Client.Get(ctx, "Silo", key.Namespace, key.Name, &s); err != nil {
		return engine.Result{}, client.IgnoreNotFound(err)
	}
	var hosts []*v1.Host
	if c.Hosts != nil {
		for _, o := range c.Hosts.List() {
			hosts = append(hosts, o.(*v1.Host))
		}
	}
	next, changed := Settle(&s, c.gate(), hosts)
	if !changed {
		return engine.Result{}, nil
	}
	s.Status = next
	return engine.Result{}, c.Client.UpdateStatus(ctx, &s)
}

// Map wakes every silo when a host reports or the gate changes.
func (c *Controller) Map(changed engine.Key) []engine.Key {
	if (changed.Kind != "Host" && changed.Kind != "RestoreGate") || c.Silos == nil {
		return nil
	}
	var keys []engine.Key
	for _, o := range c.Silos.List() {
		s := o.(*v1.Silo)
		keys = append(keys, engine.Key{Kind: "Silo", Namespace: s.Namespace, Name: s.Name})
	}
	return keys
}

func (c *Controller) gate() *v1.RestoreGate {
	if c.Gates == nil {
		return nil
	}
	o, ok := c.Gates.Get("", v1.RestoreGateName)
	if !ok {
		return nil
	}
	g, _ := o.(*v1.RestoreGate)
	return g
}
