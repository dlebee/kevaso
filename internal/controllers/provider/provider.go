// Package provider holds the control plane's controllers for provider plugins (design §12): which
// hosts are a plugin's own machines, load balancers from a plugin's class, volumes from a plugin's
// storage class, and DNS records for Ingress host names. The plugins hold the cloud token and call
// the cloud's API; these controllers decide when, and keep the API's objects saying what is where.
//
// Volumes carry a finalizer on the silo (kevaso.com/volumes), so deleting the silo deletes them
// first. A load balancer is its IP's (design §7.2c-1): keyed by the IP's UID, ensured while the
// silo holds the IP; the IP controller lets go of it (unshares or parks it) when the silo goes, and
// releases it with the IP.
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

// FinalizerVolumes holds a silo until its plugin volumes are deleted.
const FinalizerVolumes = "kevaso.com/volumes"

// Classes are the registered plugins' classes, for the scheduler.
func Classes(r *plugins.Registry) map[string]scheduler.Class {
	out := map[string]scheduler.Class{}
	for _, p := range r.All() {
		for _, c := range p.Info.LoadBalancers {
			out[c.Name] = scheduler.Class{Plugin: p.Info.Name, OwnHostsOnly: c.OwnHostsOnly, NodePorts: c.NodePorts,
				Reserve: c.Reserve, Follows: c.Follows, SendsFrom: c.SendsFrom, Exclusive: c.Exclusive}
		}
		for _, c := range p.Info.Storage {
			out[c.Name] = scheduler.Class{Plugin: p.Info.Name, OwnHostsOnly: c.OwnHostsOnly, Topology: c.Topology, Mount: c.Mounted()}
		}
	}
	return out
}

// ── Hosts ────────────────────────────────────────────────────────────────────

// Hosts records, on each Host, whether it's one of a plugin's machines (status.provider).
type Hosts struct {
	Client  *client.Client
	Hosts   *informer.Informer
	Plugins *plugins.Registry
	Every   time.Duration // look again this often (default 5m)

	mu   sync.Mutex
	seen map[string]asked // host → what it was last described with, and when
}

// asked remembers a call to a plugin: what it was asked, and when.
type asked struct {
	key string
	at  time.Time
}

// fresh reports whether key was asked less than every ago (and remembers it was, if not).
func remember(mu *sync.Mutex, m *map[string]asked, id, key string, every time.Duration) bool {
	mu.Lock()
	defer mu.Unlock()
	if *m == nil {
		*m = map[string]asked{}
	}
	if a, ok := (*m)[id]; ok && a.key == key && time.Since(a.at) < every {
		return true
	}
	return false
}

func record(mu *sync.Mutex, m *map[string]asked, id, key string) {
	mu.Lock()
	defer mu.Unlock()
	if *m == nil {
		*m = map[string]asked{}
	}
	(*m)[id] = asked{key: key, at: time.Now()}
}

// pluginsKey changes when a plugin comes, goes or changes.
func pluginsKey(r *plugins.Registry) string {
	var b strings.Builder
	for _, p := range r.All() {
		b.WriteString(p.Info.Name + "@" + p.Info.Version + ";")
	}
	return b.String()
}

// Name implements engine.Controller.
func (c *Hosts) Name() string { return "provider-hosts" }

// Kind implements engine.Controller.
func (c *Hosts) Kind() string { return "Host" }

// Reconcile implements engine.Controller.
func (c *Hosts) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	every := c.Every
	if every <= 0 {
		every = 5 * time.Minute
	}
	o, ok := c.Hosts.Get("", k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	h := o.(*v1.Host)
	// Heartbeats change the Host every 30 s; the plugins only need asking when its address or the
	// plugins changed, and now and then.
	key := h.Spec.Address + "|" + pluginsKey(c.Plugins)
	if remember(&c.mu, &c.seen, h.Name, key, every) {
		return engine.Result{}, nil
	}
	var want *v1.HostProvider
	for _, p := range c.Plugins.All() {
		if !p.Info.Hosts {
			continue
		}
		infos, err := p.Conn.DescribeHosts(ctx, []kplugin.Host{{Name: h.Name, Address: h.Spec.Address}})
		if err != nil {
			return engine.Result{}, fmt.Errorf("plugin %s: %w", p.Info.Name, err)
		}
		for _, i := range infos {
			if i.Name == h.Name {
				want = &v1.HostProvider{Name: p.Info.Name, ID: i.ID, Region: i.Region, PrivateAddress: i.PrivateAddress}
			}
		}
		if want != nil {
			break
		}
	}
	if !same(h.Status.Provider, want) {
		h.Status.Provider = want
		if err := c.Client.UpdateStatus(ctx, h); err != nil {
			return engine.Result{}, err
		}
	}
	record(&c.mu, &c.seen, h.Name, key)
	return engine.Result{RequeueAfter: every}, nil
}

func same(a, b *v1.HostProvider) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func info(h *v1.Host) kplugin.HostInfo {
	p := h.Status.Provider
	return kplugin.HostInfo{Name: h.Name, ID: p.ID, Region: p.Region, PrivateAddress: p.PrivateAddress}
}

// ── Shared helpers ───────────────────────────────────────────────────────────

// ipAddress records a load balancer's address on the IP it is, for a class that can't reserve:
// the balancer is the IP's, so its address is.
func ipAddress(ctx context.Context, c *client.Client, ip *v1.IP, addr string, h *v1.Host) error {
	region := ""
	if h != nil && h.Status.Provider != nil {
		region = h.Status.Provider.Region
	}
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.IP
		if err := c.Get(ctx, "IP", ip.Namespace, ip.Name, &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		if cur.UID != ip.UID || (cur.Status.Address == addr && (cur.Status.Region == region || region == "")) {
			return nil
		}
		cur.Status.Address = addr
		if region != "" {
			cur.Status.Region = region
		}
		err := c.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return err
	}
	return errors.New("IP kept changing; will retry")
}

// updateStatus applies mutate to the latest copy of s's status (retrying conflicts).
func updateStatus(ctx context.Context, c *client.Client, s *v1.Silo, mutate func(*v1.SiloStatus)) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Silo
		if err := c.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
			return err
		}
		if cur.UID != s.UID {
			return nil
		}
		before := statusKey(cur.Status)
		mutate(&cur.Status)
		if statusKey(cur.Status) == before {
			return nil
		}
		err := c.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return err
	}
	return errors.New("status kept changing; will retry")
}

// setFinalizers removes one finalizer and/or adds one on the latest copy of s.
func setFinalizers(ctx context.Context, c *client.Client, s *v1.Silo, remove, add string) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Silo
		if err := c.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
			if client.IsNotFound(err) {
				return nil
			}
			return err
		}
		if cur.UID != s.UID {
			return nil
		}
		var fs []string
		has := false
		for _, f := range cur.Finalizers {
			if f == remove {
				continue
			}
			has = has || f == add
			fs = append(fs, f)
		}
		if add != "" && !has {
			if cur.DeletionTimestamp != nil {
				return nil // being deleted: no new finalizers
			}
			fs = append(fs, add)
		}
		if len(fs) == len(cur.Finalizers) && (add == "" || has) {
			return nil
		}
		cur.Finalizers = fs
		err := c.Update(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		if client.IsNotFound(err) {
			return nil
		}
		return err
	}
	return errors.New("silo kept changing; will retry")
}

var _ engine.Controller = (*Hosts)(nil)
