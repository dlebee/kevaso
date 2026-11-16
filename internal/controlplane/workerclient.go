package controlplane

import (
	"net/http"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

// workerClient is the in-process client of this node's worker (and its agent): it writes as host
// (a worker), never as the control plane's own Component, so what it may write is judged as a
// worker-only host's is; its answers are stamped as the API's are, and judged by wm, like a
// worker-only host's (§0.7). The controllers' own client is not judged: they are the control plane.
func workerClient(srv *apiserver.Server, st store.Store, wm *agent.Watermark, host string) (*client.Client, func()) {
	return inProcessHost(srv, st, wm, host, "worker")
}

// inProcessHost is an in-process client authenticated as this host. role is "worker" for the
// worker component, or "control-plane" for the system node itself. Cluster-secret delivery uses
// it: ?for=PLUGIN accepts either host certificate and refuses kevasod's own component identity.
// Answers are stamped and judged by wm, so a held or foreign answer applies nothing.
func inProcessHost(srv *apiserver.Server, st store.Store, wm *agent.Watermark, host, role string) (*client.Client, func()) {
	id := pki.Identity{Type: "host", Name: host, Role: role}
	// refuse: a write whose answer can't be stamped is not made (503 before any handler), as on
	// the API listener: else it would land, come back unstamped (NotYet), and be sent again.
	c, closeC := srv.InProcessAs(id, func(h http.Handler) http.Handler { return withControlPlane(h, st, true) })
	c.ControlPlane = wm
	return c, closeC
}
