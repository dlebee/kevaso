// Package plugins is the control plane's registry of provider plugins (design §12, registration
// copied from the kubelet's plugin watcher): it watches kplugin.Dir for NAME/plugin.sock, asks each
// new socket for its Info, and from then on routes load-balancer and storage classes and DNS
// provider names to the plugin that serves them. A plugin that stops answering (its Info fails, or
// its socket is gone: a restart, an upgrade) keeps its last answer for Hold, ten minutes by default,
// and says so in the log and in every error a call to it returns; it is dropped only when it hasn't
// answered for that long (K-040). A worker's agent keeps one too, for the plugins' node sides
// (NAME/node.sock), which mount the volumes of mount-reach storage classes.
package plugins

import (
	"cmp"
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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
	kplugin.Addresses
	kplugin.Volumes
	kplugin.DNS
	kplugin.Node
}

// Plugin is one registered plugin.
type Plugin struct {
	Info kplugin.Info
	Conn Conn
}

// Away says since when the plugin hasn't answered the registry, and why (zero: it answers).
func (p *Plugin) Away() (since time.Time, why string) {
	if g, ok := p.Conn.(*guarded); ok {
		return g.away()
	}
	return time.Time{}, ""
}

// DefaultManifests is where kvoadm keeps plugins' manifests on a host (root's, 0700).
const DefaultManifests = "/etc/kevaso/plugins"

// DefaultHold is how long a plugin that stops answering keeps what it serves (K-040).
const DefaultHold = 10 * time.Minute

// Registry is the registered plugins.
type Registry struct {
	Dir      string        // default kplugin.Dir
	Socket   string        // the socket's name in Dir/NAME (default kplugin.ControllerSocket)
	Every    time.Duration // how often to look (default 2s)
	Log      func(string, ...any)
	OnChange func() // after a plugin is added or removed
	// Limits bound every call to a registered plugin (deadlines, calls in flight); zero: defaults.
	Limits Limits
	// Hold is how long a plugin that stops answering keeps its last answer before it is dropped
	// (default DefaultHold): one missed Info is never an outage of what it serves.
	Hold time.Duration
	// Manifests is where kvoadm plugin install stores each plugin's manifest on this host
	// (NAME/kevaso-plugin.json; default DefaultManifests): the device prefix a plugin registered from
	// its socket declares there is the only place its AttachVolume answers may point (K-038).
	Manifests string

	mu      sync.RWMutex
	plugins map[string]*Plugin // by name
	sockets map[string]string  // socket → name
	refused map[string]string  // socket → why it isn't registered (said once)
}

// Add registers a plugin directly (built-in plugins, tests).
func (r *Registry) Add(ctx context.Context, c Conn) error {
	info, err := guard("(new)", c, r.Limits).Info(ctx)
	if err != nil {
		return err
	}
	if why := r.claimed(info, ""); why != "" {
		return fmt.Errorf("plugin %s %s refused: %s", info.Name, info.Version, why)
	}
	r.put(&Plugin{Info: info, Conn: c}, "")
	return nil
}

// claimed says why a plugin answering info at sock ("": in core's process) may not register, or
// "" (K-042): a socket answers under the name of its folder, the name kvoadm installed it under;
// and no class (load-balancer and storage classes share their names) or DNS provider is served
// by two plugins. The one registered first keeps it.
func (r *Registry) claimed(info kplugin.Info, sock string) string {
	if sock != "" {
		if folder := filepath.Base(filepath.Dir(sock)); info.Name != folder {
			return fmt.Sprintf("it answers as plugin %s, but it is installed as %s (its socket's folder): a plugin answers under the name it was installed under (kvoadm plugin install --name %s)", info.Name, folder, info.Name)
		}
	}
	if err := info.Networking.Check(); err != nil {
		return "it declares networking Kevaso can't check (" + strings.ReplaceAll(err.Error(), "\n", "; ") + "): fix the plugin (its conformance tests fail too)"
	}
	type claim struct{ what, kind string }
	mine := map[string]claim{}
	for _, c := range info.LoadBalancers {
		mine["class "+c.Name] = claim{"load-balancer class " + c.Name, "a load-balancer class"}
	}
	for _, c := range info.Storage {
		mine["class "+c.Name] = claim{"storage class " + c.Name, "a storage class"}
	}
	for _, d := range info.DNS {
		mine["dns "+d] = claim{"dns provider " + d, "a dns provider"}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var why []string
	for name, p := range r.plugins {
		if same, ok := r.sockets[sock]; sock != "" && ok && same == name {
			continue // itself, restarted
		}
		if name == info.Name {
			why = append(why, fmt.Sprintf("plugin %s is registered already (%s)", name, r.socketOf(name)))
			continue
		}
		theirs := map[string]string{}
		for _, c := range p.Info.LoadBalancers {
			theirs["class "+c.Name] = "a load-balancer class"
		}
		for _, c := range p.Info.Storage {
			theirs["class "+c.Name] = "a storage class"
		}
		for _, d := range p.Info.DNS {
			theirs["dns "+d] = "a dns provider"
		}
		for k, c := range mine {
			kind, ok := theirs[k]
			if !ok {
				continue
			}
			w := fmt.Sprintf("%s: plugin %s serves it already", c.what, name)
			if kind != c.kind {
				w += " (" + kind + ")"
			}
			why = append(why, w+" ("+r.socketOf(name)+")")
		}
	}
	if len(why) == 0 {
		return ""
	}
	sort.Strings(why)
	return strings.Join(why, "; ") + ": remove one of the two plugins (kvoadm plugin remove HOST --name NAME), or give the class another name in its config"
}

// socketOf is where plugin name was registered from (under r.mu).
func (r *Registry) socketOf(name string) string {
	for sock, n := range r.sockets {
		if n == name {
			return "at " + sock
		}
	}
	return "in kevasod"
}

func (r *Registry) put(p *Plugin, socket string) {
	g := guard(p.Info.Name, p.Conn, r.Limits)
	if socket != "" { // in core's process: core's own code, no manifest
		dir := r.Manifests
		if dir == "" {
			dir = DefaultManifests
		}
		g.setManifest(filepath.Join(dir, p.Info.Name, kplugin.ManifestFile))
	}
	p.Conn = g
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
	var p *Plugin
	if ok {
		p = r.plugins[name]
		delete(r.sockets, socket)
		delete(r.plugins, name)
	}
	r.mu.Unlock()
	if p != nil {
		closeConn(p.Conn)
	}
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
	if n := i.Networking; n != nil {
		var can []string
		if n.ProviderIPs {
			can = append(can, "provider IPs")
		}
		if n.LoadBalancers {
			can = append(can, "load balancers")
		}
		parts = append(parts, fmt.Sprintf("networking: %s, %d annotations", strings.Join(append(can, "reach "+cmp.Or(n.Reach, kplugin.FollowsRegion)), ", "), len(n.Annotations)))
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
	name := r.Socket
	if name == "" {
		name = kplugin.ControllerSocket
	}
	found, _ := filepath.Glob(filepath.Join(dir, "*", name))
	seen := map[string]bool{}
	for _, sock := range found {
		seen[sock] = true
		r.mu.RLock()
		var cur *Plugin
		if name, ok := r.sockets[sock]; ok {
			cur = r.plugins[name]
		}
		r.mu.RUnlock()
		// A known plugin keeps its connection (gRPC reconnects by itself after a restart); a new
		// socket gets one, closed again unless it registers.
		var c Conn
		if cur != nil {
			c = cur.Conn
		} else {
			c = kplugin.Dial(sock)
		}
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		info, err := c.Info(cctx)
		cancel()
		if err == nil && cur != nil {
			r.answered(cur)
		}
		switch {
		case err != nil && cur != nil:
			r.missed(sock, cur, err.Error())
		case err != nil:
			closeConn(c) // not up yet
		case info.Protocol != kplugin.Protocol || skew(info) != "":
			why := skew(info)
			if info.Protocol != kplugin.Protocol {
				why = fmt.Sprintf("speaks %q, not %s", info.Protocol, kplugin.Protocol)
			}
			if cur != nil {
				r.drop(sock) // restarted as a build core doesn't serve
			} else {
				closeConn(c)
			}
			r.refuse(sock, fmt.Sprintf("plugin %s %s at %s refused: %s", info.Name, info.Version, sock, why))
		case cur == nil || !reflect.DeepEqual(cur.Info, info): // new, or restarted as something else
			if why := r.claimed(info, sock); why != "" {
				if cur != nil {
					r.drop(sock) // restarted claiming what another serves
				} else {
					closeConn(c)
				}
				r.refuse(sock, fmt.Sprintf("plugin %s %s at %s refused: %s", info.Name, info.Version, sock, why))
				continue
			}
			r.refuse(sock, "")
			r.put(&Plugin{Info: info, Conn: c}, sock)
		}
	}
	r.mu.Lock()
	for sock := range r.refused {
		if !seen[sock] {
			delete(r.refused, sock) // gone: say it again if it comes back refused
		}
	}
	r.mu.Unlock()
	r.mu.RLock()
	gone := map[string]*Plugin{}
	for sock, name := range r.sockets {
		if !seen[sock] {
			gone[sock] = r.plugins[name]
		}
	}
	r.mu.RUnlock()
	for sock, p := range gone {
		r.missed(sock, p, "its socket is gone")
	}
}

func (r *Registry) hold() time.Duration {
	if r.Hold > 0 {
		return r.Hold
	}
	return DefaultHold
}

// missed: plugin p at sock didn't answer. The first time it is marked away and kept, with what it
// serves; once it has been away for the hold it is dropped.
func (r *Registry) missed(sock string, p *Plugin, why string) {
	g, ok := p.Conn.(*guarded)
	if !ok {
		r.drop(sock)
		return
	}
	since, first := g.setAway(why, r.hold())
	switch {
	case first:
		r.logf("plugin %s %s not answering (%s): %s; what it serves (%s) is kept until %s, dropped then unless it answers",
			p.Info.Name, p.Info.Version, sock, why, describe(p.Info), since.Add(r.hold()).Format(time.RFC3339))
	case time.Since(since) >= r.hold():
		r.drop(sock)
		r.logf("plugin %s: no answer for %s (%s): dropped", p.Info.Name, r.hold(), why)
	}
}

// answered: a plugin that was away answers again.
func (r *Registry) answered(p *Plugin) {
	if g, ok := p.Conn.(*guarded); ok {
		if since, was := g.clearAway(); was {
			r.logf("plugin %s answering again (after %s)", p.Info.Name, time.Since(since).Round(time.Second))
		}
	}
}

// skew says why core can't serve a plugin of info's sdk wire revision, or "".
func skew(info kplugin.Info) string {
	switch {
	case info.Revision == 0:
		return fmt.Sprintf("built against an sdk from before wire revisions; this kevasod serves revisions %d to %d: rebuild the plugin against this release's kevaso.com/core/sdk", kplugin.MinRevision, kplugin.Revision)
	case info.Revision < kplugin.MinRevision || info.Revision > kplugin.Revision:
		return fmt.Sprintf("built against sdk wire revision %d; this kevasod serves revisions %d to %d: rebuild the plugin against this release's kevaso.com/core/sdk (or upgrade kevasod)", info.Revision, kplugin.MinRevision, kplugin.Revision)
	}
	return ""
}

// refuse says why the plugin at sock isn't registered, once per reason ("" forgets it).
func (r *Registry) refuse(sock, why string) {
	r.mu.Lock()
	if r.refused == nil {
		r.refused = map[string]string{}
	}
	said := r.refused[sock] == why
	if why == "" {
		delete(r.refused, sock)
	} else {
		r.refused[sock] = why
	}
	r.mu.Unlock()
	if why != "" && !said {
		r.logf("%s", why)
	}
}

func closeConn(c Conn) {
	if cl, ok := c.(interface{ Close() error }); ok {
		_ = cl.Close()
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

// VolumeDevicePrefixes is the device prefixes the plugin for class declares on this host.
// checked is false when this host has no such plugin: there is no manifest to check a device against.
func (r *Registry) VolumeDevicePrefixes(class string) (prefixes []string, checked bool, err error) {
	if r == nil || class == "" {
		return nil, false, nil
	}
	p, _, ok := r.Storage(class)
	if !ok || p == nil {
		return nil, false, nil
	}
	g, ok := p.Conn.(*guarded)
	if !ok {
		return nil, false, nil
	}
	return g.devicePrefixes()
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

// MountClasses are the mount-reach storage classes the registered plugins serve, sorted: on a
// worker's registry of node sides, the classes this host can mount.
func (r *Registry) MountClasses() []string {
	var out []string
	for _, p := range r.All() {
		for _, c := range p.Info.Storage {
			if c.Mounted() {
				out = append(out, c.Name)
			}
		}
	}
	sort.Strings(out)
	return out
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
