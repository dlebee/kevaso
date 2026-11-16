package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/internal/plugins"
)

// csDelivered is one cluster secret as this agent last left it on disk.
type csDelivered struct {
	version   int64
	restarted bool // the unit was restarted onto these bytes (or the bytes had not changed)
}

// csSeenDel is a ClusterSecret delete this agent saw on a watch it accepts.
type csSeenDel struct {
	hist string
	rv   int64 // the deleted object's revision: a later one is the name created again
}

// clusterSecretRetry is how often a fetch that failed is tried again.
const clusterSecretRetry = 5 * time.Second

// RunClusterSecrets fetches each plugin's recorded cluster secrets and keeps the files the
// unit's LoadCredential lines name. PluginsEtc empty: nothing to deliver (tests that don't
// set it, and an agent that isn't kevasod's). The worker's agent runs it from Run. A system
// node with no worker runs it on its own: the plugin's controller side is installed there,
// and nothing else on that host would write the credential file.
func (a *Agent) RunClusterSecrets(ctx context.Context) {
	if a.PluginsEtc == "" || a.Client == nil {
		return
	}
	if a.started.IsZero() {
		a.started = time.Now()
		if a.Clock != nil {
			a.started = a.Clock.Now()
		}
	}
	every := a.ClusterSecretEvery
	if every <= 0 {
		every = clusterSecretRetry
	}
	a.csWake = make(chan struct{}, 1)
	a.csInf = informer.New(a.Client, "ClusterSecret")
	a.csInf.AddHandler(func(informer.Key) { a.wakeClusterSecrets() })
	go a.csInf.Run(ctx)
	go a.watchClusterSecretDeletes(ctx)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		a.deliverClusterSecrets(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-a.csWake:
		}
	}
}

func (a *Agent) wakeClusterSecrets() {
	if a.csWake == nil {
		return
	}
	select {
	case a.csWake <- struct{}{}:
	default:
	}
}

// clusterSecretWant is one name one side of a plugin loads.
type clusterSecretWant struct {
	plugin, side, name, path, unit string
}

// clusterSecretGroup is one secret file (a plugin and a name) and the units that load it.
type clusterSecretGroup struct {
	plugin, name, path string
	units              []string
}

// clusterSecretWants reads the records kvoadm wrote. A missing directory is a host with no
// plugins; anything else is logged and tried again.
func (a *Agent) clusterSecretWants() []clusterSecretWant {
	ents, err := os.ReadDir(a.PluginsEtc)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			a.log("cluster secrets: %s: %v", a.PluginsEtc, err)
		}
		return nil
	}
	var out []clusterSecretWant
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		plugin := e.Name()
		for _, side := range []string{"", "node"} {
			b, err := os.ReadFile(plugins.ClusterSecretsPath(a.PluginsEtc, plugin, side))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				a.log("plugin %s: cluster secrets: %v", plugin, err)
				continue
			}
			names, err := plugins.DecodeClusterSecrets(b)
			if err != nil {
				a.log("plugin %s: cluster secrets: %v", plugin, err)
				continue
			}
			for _, n := range names {
				if !plugins.ValidClusterSecretName(n) {
					a.log("plugin %s: cluster secret %q ignored", plugin, n)
					continue
				}
				out = append(out, clusterSecretWant{
					plugin: plugin, side: side, name: n,
					path: filepath.Join(a.PluginsEtc, plugin, n),
					unit: pluginUnitName(plugin, side),
				})
			}
		}
	}
	return out
}

func pluginUnitName(plugin, side string) string {
	if side == "node" {
		return "kevaso-plugin-" + plugin + "-node.service"
	}
	return "kevaso-plugin-" + plugin + ".service"
}

func groupClusterSecrets(ws []clusterSecretWant) []clusterSecretGroup {
	m := map[string]*clusterSecretGroup{}
	var order []string
	for _, w := range ws {
		k := w.plugin + "\x00" + w.name
		g, ok := m[k]
		if !ok {
			g = &clusterSecretGroup{plugin: w.plugin, name: w.name, path: w.path}
			m[k] = g
			order = append(order, k)
		}
		if !slices.Contains(g.units, w.unit) {
			g.units = append(g.units, w.unit)
		}
	}
	out := make([]clusterSecretGroup, 0, len(order))
	for _, k := range order {
		g := *m[k]
		sort.Strings(g.units)
		out = append(out, g)
	}
	return out
}

func (a *Agent) deliverClusterSecrets(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	for _, g := range groupClusterSecrets(a.clusterSecretWants()) {
		a.deliverOne(ctx, g)
	}
}

// deliverOne fetches g and writes it, or removes the cached file. A removal happens only
// when this agent is not held and the answer is from the history it accepts (the seen-delete
// rule) and it is in contact: held or cut off, the file stays so the plugin keeps its last
// value. Unchanged bytes are left where they are, and the unit is not restarted.
func (a *Agent) deliverOne(ctx context.Context, g clusterSecretGroup) {
	if s, ok := a.seenClusterSecret(g.name); ok && s.hist == a.watermark().history() {
		// The cache still holding the deleted revision is not the name created again.
		if rv, exists := a.clusterSecretRV(g.name); exists && rv != s.rv {
			a.forgetClusterSecretSeen(g.name)
		} else {
			if a.mayDropClusterSecretNow() {
				a.removeClusterSecret(ctx, g)
			}
			return
		}
	}
	if sv, ok := a.clusterSecretVersion(g.name); ok && a.clusterSecretDelivered(g, sv) {
		return
	}
	m := a.watermark().mark()
	v, err := a.fetchClusterSecret(ctx, g.plugin, g.name)
	if err != nil {
		// The mark is from before the request: an answer that itself puts this agent on
		// hold (a control plane older than what it kept) is not a reason to drop the cache.
		drop := a.watermark().acceptedSince(m) && a.inContact()
		if drop && (forbidden(err) || client.IsNotFound(err) && a.seenClusterSecretNow(g.name)) {
			a.removeClusterSecret(ctx, g)
			return
		}
		if !client.IsNotFound(err) {
			a.log("plugin %s: cluster secret %s: %v", g.plugin, g.name, err)
		}
		return
	}
	defer clear(v.Value)
	if !a.watermark().acceptedSince(m) {
		return // held, or another history: apply nothing from this answer
	}
	cur, rerr := os.ReadFile(g.path)
	missing := errors.Is(rerr, os.ErrNotExist)
	if rerr != nil && !missing {
		a.log("plugin %s: cluster secret %s: %v", g.plugin, g.name, rerr)
		return
	}
	defer clear(cur)
	same := !missing && bytes.Equal(cur, v.Value)
	if !same {
		if err := writeClusterSecretFile(g.path, v.Value); err != nil {
			a.log("plugin %s: cluster secret %s: %v", g.plugin, g.name, err)
			return
		}
		a.setRestarted(g, false)
	}
	ver := v.Version
	if sv, ok := a.clusterSecretVersion(g.name); ok {
		ver = sv
	}
	d := a.deliveryState(g)
	if same && d.restarted && d.version == ver {
		return
	}
	if !same || !d.restarted {
		for _, u := range g.units {
			if err := a.restartPlugin(ctx, u); err != nil {
				a.rememberClusterSecret(g, ver, false)
				a.log("plugin %s: %s: %v", g.plugin, u, err)
				return
			}
		}
	}
	a.rememberClusterSecret(g, ver, true)
	if !same {
		a.log("plugin %s: cluster secret %s written", g.plugin, g.name)
	}
}

func (a *Agent) fetchClusterSecret(ctx context.Context, plugin, name string) (client.SecretValue, error) {
	var v client.SecretValue
	p := "/apis/kevaso/v1/clustersecrets/" + url.PathEscape(name) + "/value?for=" + url.QueryEscape(plugin)
	err := a.Client.Call(ctx, http.MethodGet, p, nil, &v)
	return v, err
}

func forbidden(err error) bool {
	var e *client.Error
	return errors.As(err, &e) && e.Code == http.StatusForbidden
}

// mayDropClusterSecretNow is the seen-delete gate at the moment of a removal: not held, the
// history still the one this agent accepts, and in contact with the control plane.
func (a *Agent) mayDropClusterSecretNow() bool {
	w := a.watermark()
	return w.acceptedSince(w.mark()) && a.inContact()
}

func (a *Agent) removeClusterSecret(ctx context.Context, g clusterSecretGroup) {
	err := os.Remove(g.path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		a.log("plugin %s: cluster secret %s: remove: %v", g.plugin, g.name, err)
		return
	}
	a.forgetDelivered(g)
	a.log("plugin %s: cluster secret %s removed", g.plugin, g.name)
	for _, u := range g.units {
		if err := a.restartPlugin(ctx, u); err != nil {
			a.log("plugin %s: %s: %v", g.plugin, u, err)
		}
	}
}

func (a *Agent) csKey(g clusterSecretGroup) string { return g.plugin + "\x00" + g.name }

func (a *Agent) deliveryState(g clusterSecretGroup) csDelivered {
	a.csMu.Lock()
	defer a.csMu.Unlock()
	return a.csHave[a.csKey(g)]
}

func (a *Agent) clusterSecretDelivered(g clusterSecretGroup, version int64) bool {
	d := a.deliveryState(g)
	if !d.restarted || d.version != version {
		return false
	}
	_, err := os.Stat(g.path)
	return err == nil
}

func (a *Agent) rememberClusterSecret(g clusterSecretGroup, version int64, restarted bool) {
	a.csMu.Lock()
	defer a.csMu.Unlock()
	if a.csHave == nil {
		a.csHave = map[string]csDelivered{}
	}
	a.csHave[a.csKey(g)] = csDelivered{version: version, restarted: restarted}
}

func (a *Agent) setRestarted(g clusterSecretGroup, restarted bool) {
	a.csMu.Lock()
	defer a.csMu.Unlock()
	if a.csHave == nil {
		a.csHave = map[string]csDelivered{}
	}
	d := a.csHave[a.csKey(g)]
	d.restarted = restarted
	a.csHave[a.csKey(g)] = d
}

func (a *Agent) forgetDelivered(g clusterSecretGroup) {
	a.csMu.Lock()
	defer a.csMu.Unlock()
	delete(a.csHave, a.csKey(g))
}

func (a *Agent) seenClusterSecret(name string) (csSeenDel, bool) {
	a.csMu.Lock()
	defer a.csMu.Unlock()
	h, ok := a.csSeen[name]
	return h, ok
}

func (a *Agent) seenClusterSecretNow(name string) bool {
	h, ok := a.seenClusterSecret(name)
	return ok && h.hist == a.watermark().history()
}

func (a *Agent) noteClusterSecretDelete(name, hist string, rv int64) {
	a.csMu.Lock()
	defer a.csMu.Unlock()
	if a.csSeen == nil {
		a.csSeen = map[string]csSeenDel{}
	}
	a.csSeen[name] = csSeenDel{hist: hist, rv: rv}
}

func (a *Agent) forgetClusterSecretSeen(name string) {
	a.csMu.Lock()
	defer a.csMu.Unlock()
	delete(a.csSeen, name)
}

// clusterSecretRV is the cached object's revision, once the informer has synced and has it.
func (a *Agent) clusterSecretRV(name string) (int64, bool) {
	if a.csInf == nil || !a.csInf.Synced() {
		return 0, false
	}
	o, ok := a.csInf.Get("", name)
	if !ok {
		return 0, false
	}
	rv, err := strconv.ParseInt(o.GetObjectMeta().ResourceVersion, 10, 64)
	if err != nil {
		return 0, false
	}
	return rv, true
}

func (a *Agent) clusterSecretVersion(name string) (int64, bool) {
	if a.csInf == nil || !a.csInf.Synced() {
		return 0, false
	}
	o, ok := a.csInf.Get("", name)
	if !ok {
		return 0, false
	}
	cs, ok := o.(*v1.ClusterSecret)
	if !ok {
		return 0, false
	}
	return cs.Status.Version, true
}

// watchClusterSecretDeletes records a delete only from the watch, opened on a history this
// agent accepts, and only while it is not held. A list that no longer has the name is not a
// delete seen (a restore says the same of a secret nobody deleted).
func (a *Agent) watchClusterSecretDeletes(ctx context.Context) {
	for ctx.Err() == nil {
		var ch <-chan client.Event
		wctx, stop := context.WithCancel(ctx)
		wm := a.watermark()
		m0 := wm.mark()
		l, err := a.Client.List(wctx, "ClusterSecret", "")
		if err == nil {
			ch, err = a.Client.Watch(wctx, "ClusterSecret", "", l.Metadata.ResourceVersion)
		}
		hist := wm.history()
		if err == nil && !wm.acceptedSince(m0) {
			stop()
			if ch != nil {
				for range ch {
				}
			}
			if now := wm.mark(); now.refusals == m0.refusals && !a.ControlPlaneHeld() {
				continue // a history was accepted as the watch opened: open it again
			}
			ch, err = nil, errors.New("the cluster-secret delete watch opened on an answer this worker doesn't act on")
		}
		if err == nil {
			for ev := range ch {
				if wm.mark().histories != m0.histories {
					break
				}
				if ev.Type != "DELETED" || a.ControlPlaneHeld() {
					continue
				}
				o, _, decErr := v1.Decode(ev.Object)
				if decErr != nil || o.GetObjectMeta().Name == "" {
					continue
				}
				rv, _ := strconv.ParseInt(o.GetObjectMeta().ResourceVersion, 10, 64)
				a.noteClusterSecretDelete(o.GetObjectMeta().Name, hist, rv)
				a.wakeClusterSecrets()
			}
		}
		stop()
		if ch != nil {
			for range ch {
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// systemctlRestart is the command that restarts a plugin unit. The secret is not an
// argument and not in the environment: hostexec replaces the environment with a fixed one.
func systemctlRestart(unit string) hostexec.Cmd {
	return hostexec.Cmd{Name: "systemctl", Args: []string{"restart", unit}}
}

func (a *Agent) restartPlugin(ctx context.Context, unit string) error {
	if a.RestartUnit != nil {
		return a.RestartUnit(ctx, unit)
	}
	code, err := hostexec.Local{}.Run(ctx, systemctlRestart(unit))
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("systemctl restart %s: exit %d", unit, code)
	}
	return nil
}

// writeClusterSecretFile writes data to path atomically (a temporary file in the same
// directory, flushed, then renamed) and leaves it mode 0600, owned by root when this
// process is root. data is the secret: it is not logged.
func writeClusterSecretFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	written := false
	defer func() {
		if !written {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(tmp, 0, 0); err != nil {
			_ = f.Close()
			return err
		}
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	written = true
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
