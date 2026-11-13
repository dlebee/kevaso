package agent

import (
	"context"
	"sort"
	"strings"
	"time"

	v1 "kevaso.com/core/api/v1"
)

// One tunnel per system node (ADR 0006). A `kvo exec` can reach any system node, and that node
// relays it over the host's tunnel to it; so the agent keeps a tunnel open to every system node
// that serves the API, found from the Hosts (status.controlPlane.apiURL). Chosen over routing
// between system nodes because:
//   - no hop from one control plane to another: no second authentication between them, and a
//     node never depends on another one being up to reach a host;
//   - losing a system node loses only its own tunnels: every other node already has one, so exec
//     keeps working with no reconnect;
//   - system nodes are few (3 or 5, light nodes serve no API), so a few connections per host cost
//     nothing, and they are dial-out like the one before, so hosts behind NAT still need no port.
//
// With no system node advertising an API URL (one control plane, or not reported yet) the agent
// keeps one tunnel through its own client, as before.

// TunnelTargets are the API URLs to hold a tunnel to, from the Hosts (pure): every system node
// that serves the API and reported its URL, sorted.
func TunnelTargets(hosts []v1.Host) []string {
	var out []string
	for _, h := range hosts {
		cp := h.Spec.Components.ControlPlane
		if cp == nil || cp.StateOnly || h.Status.ControlPlane == nil || h.Status.ControlPlane.APIURL == "" {
			continue
		}
		out = append(out, h.Status.ControlPlane.APIURL)
	}
	sort.Strings(out)
	return out
}

// RunTunnels keeps the set of tunnels matching TunnelTargets, looking again every
// TunnelRefresh (default 15s).
func (a *Agent) RunTunnels(ctx context.Context) {
	every := a.TunnelRefresh
	if every <= 0 {
		every = 15 * time.Second
	}
	running := map[string]context.CancelFunc{}
	defer func() {
		for _, c := range running {
			c()
		}
	}()
	for {
		want := a.tunnelTargets(ctx)
		if want != nil {
			keep := map[string]bool{}
			for _, u := range want {
				keep[u] = true
				if _, ok := running[u]; !ok {
					tctx, cancel := context.WithCancel(ctx)
					running[u] = cancel
					c := a.Client
					if u != "" {
						c = a.Client.Pinned(u)
					}
					go a.runTunnel(tctx, c)
				}
			}
			for u, cancel := range running {
				if !keep[u] {
					cancel()
					delete(running, u)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// tunnelTargets: the system nodes' URLs; [""] (this agent's own client) when none reported one;
// nil when the Hosts can't be read (keep what runs).
func (a *Agent) tunnelTargets(ctx context.Context) []string {
	if !strings.HasPrefix(a.Client.BaseURL, "https://") {
		// The worker inside a control plane talks to it in process: one tunnel, to that one.
		// (Exec at another system node to its silos isn't routed yet: ADR 0006.)
		return []string{""}
	}
	l, err := a.Client.List(ctx, "Host", "")
	if err != nil {
		if len(a.tunnelsSeen) == 0 {
			a.tunnelsSeen = []string{""}
			return a.tunnelsSeen
		}
		return nil
	}
	var hosts []v1.Host
	for _, raw := range l.Items {
		if obj, _, err := v1.Decode(raw); err == nil {
			if h, ok := obj.(*v1.Host); ok {
				hosts = append(hosts, *h)
			}
		}
	}
	t := TunnelTargets(hosts)
	if len(t) == 0 {
		t = []string{""}
	}
	a.tunnelsSeen = t
	return t
}
