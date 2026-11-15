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
	id := pki.Identity{Type: "host", Name: host, Role: "worker"}
	c, closeC := srv.InProcessAs(id, func(h http.Handler) http.Handler { return withControlPlane(h, st, false) })
	c.ControlPlane = wm
	return c, closeC
}
