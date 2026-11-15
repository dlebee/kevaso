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
// identity is read from the store for each answer, never kept from this node's start: a restore
// made through another system node writes a new history into the store this one serves, and this
// node must say it at once (a worker that accepted it would otherwise judge this node older). The
// revision is read after it, so it is one the answer is at least as new as; reads are
// linearizable in both stores, so two answers in a row never go down within one history,
// whichever system node gives them. If the store gives either not within the deadline, the answer
// carries no stamp at all, and a worker judges it NotYet: never as if it were judged.
func withControlPlane(h http.Handler, st store.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		id, _, found, err := readIdentity(ctx, st)
		if err == nil && found {
			if rev, err := st.Revision(ctx); err == nil {
				client.SetControlPlane(w.Header(), client.ControlPlaneSeen{ClusterID: id.ID, History: id.History, Epoch: id.Epoch, Revision: rev})
			}
		}
		cancel()
		h.ServeHTTP(w, r)
	})
}
