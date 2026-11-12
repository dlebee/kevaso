// Package plugins is the control plane's registry of provider plugins (design §12, registration
// copied from the kubelet's plugin watcher): it watches kplugin.Dir for NAME/plugin.sock, asks each
// new socket for its Info, and from then on routes load-balancer and storage classes and DNS
// provider names to the plugin that serves them. A plugin that stops answering is dropped until its
// socket answers again.
package plugins

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"kevaso.com/core/sdk/kplugin"
)

// Conn is a plugin connection: every interface (calls a plugin doesn't serve fail with
// kplugin.ErrUnsupported).
type Conn interface {
	kplugin.Plugin
	kplugin.HostDescriber
	kplugin.LoadBalancers
	kplugin.Volumes
	kplugin.DNS
}

// Plugin is one registered plugin.
type Plugin struct {
	Info kplugin.Info
	Conn Conn
}

// Registry is the registered plugins.
type Registry struct {
	Dir      string        // default kplugin.Dir
	Every    time.Duration // how often to look (default 2s)
	Log      func(string, ...any)
	OnChange func() // after a plugin is added or removed

	mu      sync.RWMutex
	plugins map[string]*Plugin // by name
	sockets map[string]string  // socket → name
}

// Add registers a plugin directly (built-in plugins, tests).
func (r *Registry) Add(ctx context.Context, c Conn) error {
	info, err := c.Info(ctx)
	if err != nil {
		return err
	}
	r.put(&Plugin{Info: info, Conn: c}, "")
	return nil
}

func (r *Registry) put(p *Plugin, socket string) {
	r.mu.Lock()
	if r.plugins == nil {
		r.plugins, r.sockets = map[string]*Plugin{}, map[string]string{}
	}
	r.plugins[p.Info.Name] = p
	if socket != "" {
		r.sockets[socket] = p.Info.Name
	}
	r.mu.Unlock()
	r.logf("plugin %s %s registered (%s)", p.Info.Name, p.Info.Version, describe(p.Info))
	if r.OnChange != nil {
		r.OnChange()
	}
}

func (r *Registry) drop(socket string) {
	r.mu.Lock()
	name, ok := r.sockets[socket]
	if ok {
		delete(r.sockets, socket)
		delete(r.plugins, name)
	}
	r.mu.Unlock()
	if ok {
		r.logf("plugin %s gone (%s)", name, socket)
		if r.OnChange != nil {
			r.OnChange()
		}
	}
}

func (r *Registry) logf(f string, a ...any) {
	if r.Log != nil {
		r.Log(f, a...)
	}
}

func describe(i kplugin.Info) string {
	var parts []string
	for _, c := range i.LoadBalancers {
		parts = append(parts, "load balancer "+c.Name)
	}
	for _, c := range i.Storage {
		parts = append(parts, "storage "+c.Name)
	}
	for _, d := range i.DNS {
		parts = append(parts, "dns "+d)
	}
	if i.Hosts {
		parts = append(parts, "hosts")
	}
	if len(parts) == 0 {
		return "nothing"
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return out
}

// Run watches the plugin folder until ctx ends.
func (r *Registry) Run(ctx context.Context) {
	dir, every := r.Dir, r.Every
	if dir == "" {
		dir = kplugin.Dir
	}
	if every <= 0 {
		every = 2 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		r.scan(ctx, dir)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (r *Registry) scan(ctx context.Context, dir string) {
	found, _ := filepath.Glob(filepath.Join(dir, "*", "plugin.sock"))
	seen := map[string]bool{}
	for _, sock := range found {
		seen[sock] = true
		r.mu.RLock()
		_, known := r.sockets[sock]
		r.mu.RUnlock()
		c := kplugin.Dial(sock)
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		info, err := c.Info(cctx)
		cancel()
		switch {
		case err != nil && known:
			r.drop(sock)
		case err != nil:
			// not up yet
		case info.Protocol != kplugin.Protocol:
			if !known {
				r.logf("plugin at %s speaks %q, not %s: ignored", sock, info.Protocol, kplugin.Protocol)
			}
		case !known:
			r.put(&Plugin{Info: info, Conn: c}, sock)
		}
	}
	r.mu.RLock()
	var gone []string
	for sock := range r.sockets {
		if !seen[sock] {
			gone = append(gone, sock)
		}
	}
	r.mu.RUnlock()
	for _, sock := range gone {
		r.drop(sock)
	}
}

// All returns the registered plugins, by name.
func (r *Registry) All() []*Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Info.Name < out[j].Info.Name })
	return out
}

// LoadBalancer is the plugin serving a load-balancer class.
func (r *Registry) LoadBalancer(class string) (*Plugin, kplugin.Class, bool) {
	for _, p := range r.All() {
		for _, c := range p.Info.LoadBalancers {
			if c.Name == class {
				return p, c, true
			}
		}
	}
	return nil, kplugin.Class{}, false
}

// Storage is the plugin serving a storage class.
func (r *Registry) Storage(class string) (*Plugin, kplugin.Class, bool) {
	for _, p := range r.All() {
		for _, c := range p.Info.Storage {
			if c.Name == class {
				return p, c, true
			}
		}
	}
	return nil, kplugin.Class{}, false
}

// DNS is the plugin serving a DNS provider.
func (r *Registry) DNS(name string) (*Plugin, bool) {
	for _, p := range r.All() {
		for _, d := range p.Info.DNS {
			if d == name {
				return p, true
			}
		}
	}
	return nil, false
}
