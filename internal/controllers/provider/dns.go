package provider

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin"
)

// FinalizerDNS keeps an Ingress until the records it published are gone.
const FinalizerDNS = "dns.kevaso.com/records"

// IngressDNS publishes an Ingress's host names through its class's DNS provider, pointing at the
// class controller's public address (status.address), and deletes them when they go. Records are
// marked as this cluster's; a name someone else owns is left alone (the condition says so).
type IngressDNS struct {
	Client    *client.Client
	Ingresses *informer.Informer
	Classes   *informer.Informer
	Plugins   *plugins.Registry
	Cluster   string
	Clock     clock.Clock

	mu        sync.Mutex
	published map[string]asked // ingress UID → what was last published
}

// Name implements engine.Controller.
func (c *IngressDNS) Name() string { return "ingress-dns" }

// Kind implements engine.Controller.
func (c *IngressDNS) Kind() string { return "Ingress" }

// Owner marks the records of one Ingress.
func (c *IngressDNS) Owner(ing *v1.Ingress) string {
	return fmt.Sprintf("kevaso:%s/ingress/%s/%s", c.Cluster, ing.Namespace, ing.Name)
}

func recordType(addr string) string {
	if a, err := netip.ParseAddr(addr); err == nil && a.Is6() {
		return "AAAA"
	}
	return "A"
}

// Reconcile implements engine.Controller.
func (c *IngressDNS) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.Ingresses.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	ing := o.(*v1.Ingress)
	var dns *v1.IngressDNS
	if co, ok := c.Classes.Get("", ing.Spec.IngressClass); ok {
		dns = co.(*v1.IngressClass).Spec.DNS
	}
	want := map[string]bool{}
	if dns != nil && ing.DeletionTimestamp == nil && ing.Status.Address != "" {
		for _, h := range ing.Spec.Hosts {
			want[strings.TrimSuffix(strings.ToLower(h), ".")] = true
		}
	}
	has := false
	for _, f := range ing.Finalizers {
		has = has || f == FinalizerDNS
	}
	if len(want) == 0 && len(ing.Status.DNSNames) == 0 {
		if has {
			return engine.Result{}, c.finalizer(ctx, ing, false)
		}
		return engine.Result{}, nil
	}
	if len(want) > 0 && !has {
		return engine.Result{}, c.finalizer(ctx, ing, true)
	}
	provider := ""
	if dns != nil {
		provider = dns.Provider
	}
	p, ok := c.Plugins.DNS(provider)
	if !ok {
		return c.condition(ctx, ing, nil, meta.ConditionFalse, "PluginMissing", "no plugin serves DNS provider "+dashed(provider), 30*time.Second)
	}
	ttl := 300
	if dns != nil && dns.TTL > 0 {
		ttl = dns.TTL
	}
	owner := c.Owner(ing)
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	reqKey := fmt.Sprintf("%s|%v|%v|%s|%d", provider, names, ing.Status.DNSNames, ing.Status.Address, ttl)
	if ing.DeletionTimestamp == nil && remember(&c.mu, &c.published, ing.UID, reqKey, 30*time.Minute) {
		return engine.Result{}, nil // its own status write, or a change that doesn't touch DNS
	}
	var published []string
	var errs []string
	for name := range want {
		r := kplugin.Record{Provider: provider, Name: name, Type: recordType(ing.Status.Address), Values: []string{ing.Status.Address}, TTL: ttl, Owner: owner}
		if err := p.Conn.EnsureRecord(ctx, r); err != nil {
			errs = append(errs, name+": "+err.Error())
			continue
		}
		published = append(published, name)
	}
	for _, name := range ing.Status.DNSNames {
		if want[name] {
			continue
		}
		var lastErr error
		for _, typ := range []string{"A", "AAAA"} {
			err := p.Conn.DeleteRecord(ctx, kplugin.Record{Provider: provider, Name: name, Type: typ, Owner: owner})
			if err != nil && !errors.Is(err, kplugin.ErrNotFound) {
				lastErr = err
			}
		}
		if lastErr != nil {
			errs = append(errs, name+": "+lastErr.Error())
			published = append(published, name) // still there: try again
		}
	}
	sort.Strings(published)
	if len(errs) > 0 {
		sort.Strings(errs)
		_, _ = c.condition(ctx, ing, published, meta.ConditionFalse, "Failed", strings.Join(errs, "; "), 0)
		return engine.Result{}, errors.New(strings.Join(errs, "; "))
	}
	if ing.DeletionTimestamp != nil && len(published) == 0 {
		return engine.Result{}, c.finalizer(ctx, ing, false)
	}
	msg := "no names to publish"
	if len(published) > 0 {
		msg = strings.Join(published, ", ") + " → " + ing.Status.Address + " (" + provider + ")"
	}
	res, err := c.condition(ctx, ing, published, meta.ConditionTrue, "Published", msg, 30*time.Minute)
	if err == nil {
		after := fmt.Sprintf("%s|%v|%v|%s|%d", provider, names, published, ing.Status.Address, ttl)
		record(&c.mu, &c.published, ing.UID, after)
	}
	return res, err
}

func dashed(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func (c *IngressDNS) condition(ctx context.Context, ing *v1.Ingress, published []string, status meta.ConditionStatus, reason, msg string, again time.Duration) (engine.Result, error) {
	now := time.Now().UTC().Truncate(time.Second)
	if c.Clock != nil {
		now = c.Clock.Now().UTC().Truncate(time.Second)
	}
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Ingress
		if err := c.Client.Get(ctx, "Ingress", ing.Namespace, ing.Name, &cur); err != nil {
			return engine.Result{}, client.IgnoreNotFound(err)
		}
		before := statusKey(cur.Status)
		if published != nil || reason == "Published" {
			cur.Status.DNSNames = published
		}
		meta.SetCondition(&cur.Status.Conditions, meta.Condition{Type: "DNS", Status: status, Reason: reason, Message: msg, ObservedGeneration: cur.Generation}, now)
		if statusKey(cur.Status) == before {
			return engine.Result{RequeueAfter: again}, nil
		}
		err := c.Client.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return engine.Result{RequeueAfter: again}, err
	}
	return engine.Result{}, errors.New("ingress kept changing; will retry")
}

func (c *IngressDNS) finalizer(ctx context.Context, ing *v1.Ingress, add bool) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Ingress
		if err := c.Client.Get(ctx, "Ingress", ing.Namespace, ing.Name, &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		var fs []string
		has := false
		for _, f := range cur.Finalizers {
			if f == FinalizerDNS {
				has = true
				if !add {
					continue
				}
			}
			fs = append(fs, f)
		}
		if add == has || (add && cur.DeletionTimestamp != nil) {
			return nil
		}
		if add {
			fs = append(fs, FinalizerDNS)
		}
		cur.Finalizers = fs
		err := c.Client.Update(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return client.IgnoreNotFound(err)
	}
	return errors.New("ingress kept changing; will retry")
}

// Map implements engine.Mapper: a class's DNS settings reach its Ingresses.
func (c *IngressDNS) Map(changed engine.Key) []engine.Key {
	if changed.Kind != "IngressClass" {
		return nil
	}
	var keys []engine.Key
	for _, o := range c.Ingresses.List() {
		if ing := o.(*v1.Ingress); ing.Spec.IngressClass == changed.Name {
			keys = append(keys, engine.Key{Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name})
		}
	}
	return keys
}

// DNSProvider adapts a plugin's DNS provider to acme's dns01 solvers: TXT records for challenges.
type DNSProvider struct {
	Plugins *plugins.Registry
	Name    string
	Owner   string
}

// Present implements acme.DNSProvider.
func (d *DNSProvider) Present(ctx context.Context, fqdn, value string) error {
	p, ok := d.Plugins.DNS(d.Name)
	if !ok {
		return fmt.Errorf("no plugin serves DNS provider %s", d.Name)
	}
	return p.Conn.EnsureRecord(ctx, kplugin.Record{Provider: d.Name, Name: strings.TrimSuffix(fqdn, "."), Type: "TXT", Values: []string{value}, TTL: 60, Owner: d.Owner})
}

// CleanUp implements acme.DNSProvider.
func (d *DNSProvider) CleanUp(ctx context.Context, fqdn, _ string) error {
	p, ok := d.Plugins.DNS(d.Name)
	if !ok {
		return fmt.Errorf("no plugin serves DNS provider %s", d.Name)
	}
	err := p.Conn.DeleteRecord(ctx, kplugin.Record{Provider: d.Name, Name: strings.TrimSuffix(fqdn, "."), Type: "TXT", Owner: d.Owner})
	if errors.Is(err, kplugin.ErrNotFound) {
		return nil
	}
	return err
}

var (
	_ engine.Controller = (*IngressDNS)(nil)
	_ engine.Mapper     = (*IngressDNS)(nil)
)
