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
//
// refuse (the API listener): a store that gives neither answers 503 with
// client.HeaderUnavailable before anything is handled (K-008): this node can't serve (no quorum,
// or its store doesn't answer), and a worker's client sends the request to another system node
// as it is. The admin socket doesn't refuse: a person here may be repairing the store.
// StampTimeout is how long the stamp's store reads may take. Past it the store counts as not
// answering: no stamp, and on the API listener a 503. Long enough that a store slow under load
// isn't taken for one without quorum (2 s was, on a loaded test runner); short enough that a
// client's attempt (client.AttemptTimeout, 6 s) gets the 503 and goes on to another node.
const StampTimeout = 4 * time.Second

func withControlPlane(h http.Handler, st store.Store, refuse bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), StampTimeout)
		id, _, found, err := readIdentity(ctx, st)
		var rev int64
		if err == nil && found {
			rev, err = st.Revision(ctx)
		}
		cancel()
		switch {
		case err != nil && refuse:
			client.WriteUnavailable(w, "its store doesn't answer ("+err.Error()+")")
			return
		case err == nil && found:
			client.SetControlPlane(w.Header(), client.ControlPlaneSeen{ClusterID: id.ID, History: id.History, Epoch: id.Epoch, Revision: rev})
		}
		h.ServeHTTP(w, r)
	})
}
