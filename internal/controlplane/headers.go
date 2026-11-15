package controlplane

import (
	"context"
	"net/http"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/store"
)

// withControlPlane puts on every answer which cluster this is, which history of it, and the store's
// revision as the request came in (client.HeaderClusterID and the rest; brainstorm §0.7). The
// revision is read before the handler, so it is one the answer is at least as new as; reads are
// linearizable in both stores, so two answers in a row never go down within one history, whichever
// system node gives them. Without a revision (the store didn't answer) the headers say nothing a
// worker would judge by: ParseControlPlane needs all four.
func withControlPlane(h http.Handler, st store.Store, id ClusterIdentity) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := client.ControlPlaneSeen{ClusterID: id.ID, History: id.History, Epoch: id.Epoch}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		if rev, err := st.Revision(ctx); err == nil {
			s.Revision = rev
		}
		cancel()
		client.SetControlPlane(w.Header(), s)
		h.ServeHTTP(w, r)
	})
}
