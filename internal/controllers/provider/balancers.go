package provider

import (
	"context"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/plugins"
)

// Balancers runs the providers' balancers (networking v2): one per LoadBalancer service by
// default, shared and tuned by the provider's annotations, created with its service and removed
// with its last user; the worker's node port open to the balancer only; backends the ready silos.
//
// TODO(net-v2 wave 2): the balancer controller. The v1 one was keyed by IP (one balancer per IP
// of a plugin's class, every holder's ports on it); v2 keys it by service and provider, which
// that wave builds. Until then Reconcile does nothing, so a LoadBalancer service gets no balancer.
type Balancers struct {
	Client   *client.Client
	IPs      *informer.Informer
	Silos    *informer.Informer
	Services *informer.Informer
	Hosts    *informer.Informer
	Leases   *informer.Informer // optional
	Plugins  *plugins.Registry
	Clock    clock.Clock
	// Providers are the hosts' provider details as the plugins said (K-037); nil: their status.
	Providers *Providers
	// Resync is how often an unchanged balancer is ensured anyway, to repair changes made outside
	// Kevaso (default 10m).
	Resync time.Duration
}

// Name implements engine.Controller.
func (c *Balancers) Name() string { return "balancers" }

// Kind implements engine.Controller.
func (c *Balancers) Kind() string { return "IP" }

// Domain is the annotation prefix a plugin reads: NAME.kevaso.com/.
func Domain(plugin string) string { return plugin + ".kevaso.com/" }

// Reconcile implements engine.Controller.
// TODO(net-v2 wave 2): ensure the service's balancer.
func (c *Balancers) Reconcile(context.Context, engine.Key) (engine.Result, error) {
	return engine.Result{}, nil
}

// Map implements engine.Mapper.
// TODO(net-v2 wave 2): a service, its silos, leases and hosts reach its balancer.
func (c *Balancers) Map(engine.Key) []engine.Key { return nil }

var (
	_ engine.Controller = (*Balancers)(nil)
	_ engine.Mapper     = (*Balancers)(nil)
)
