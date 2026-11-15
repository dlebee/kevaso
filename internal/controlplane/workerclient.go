package controlplane

import (
	"net/http"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/store"
)

// workerClient is the in-process client of this node's worker (and its agent): its answers are
// stamped as the API's are, and judged by wm, like a worker-only host's (§0.7). The controllers'
// own client is not judged: they are the control plane.
func workerClient(srv *apiserver.Server, st store.Store, wm *agent.Watermark) (*client.Client, func()) {
	c, closeC := srv.InProcess(func(h http.Handler) http.Handler { return withControlPlane(h, st, false) })
	c.ControlPlane = wm
	return c, closeC
}
