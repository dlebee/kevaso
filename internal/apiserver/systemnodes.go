package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/jointoken"
)

// RoleSystemNode is the join-token role of a machine joining as a system node (a control plane, or
// a light state-only node). The token is spent here, never at /enroll: it brings the cluster's
// identity, sealed to a key the machine made, not a host certificate.
const RoleSystemNode = "system-node"

// SystemNodeJoiner takes a host into the store: what the control plane plugs in (it knows the etcd
// member and the identity files). A *client.Error it returns goes to the caller as it is.
type SystemNodeJoiner func(ctx context.Context, host string, recipient []byte) (client.SystemNodeJoinResponse, error)

// SetSystemNodeJoiner enables POST /join/system-node.
func (s *Server) SetSystemNodeJoiner(j SystemNodeJoiner) { s.joinNode = j }

func (s *Server) systemNodeJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "use POST"))
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var req client.SystemNodeJoinRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Host == "" || len(req.Recipient) == 0 {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "body: want token, host and recipient"))
		return
	}
	// Spend the token only once the join can happen at all: a cluster that refuses (SQLite, no
	// majority) leaves it for the retry.
	if err := s.auth.Tokens.Check(r.Context(), req.Token, req.Host, RoleSystemNode); err != nil {
		code := http.StatusUnauthorized
		if errors.Is(err, jointoken.ErrNotAllowed) {
			code = http.StatusForbidden
		}
		writeErr(w, errf(code, http.StatusText(code), "%s", err))
		return
	}
	if s.joinNode == nil {
		writeErr(w, errf(http.StatusConflict, "StoreNotHA", "this control plane keeps its state in SQLite: switch it to etcd first (kvoadm store migrate)"))
		return
	}
	resp, err := s.joinNode(r.Context(), req.Host, req.Recipient)
	if err != nil {
		var ce *client.Error
		if errors.As(err, &ce) {
			writeErr(w, errf(ce.Code, ce.Reason, "%s", ce.Message))
			return
		}
		writeErr(w, err)
		return
	}
	if err := s.auth.Tokens.Redeem(r.Context(), req.Token, req.Host, RoleSystemNode); err != nil {
		writeErr(w, errf(http.StatusUnauthorized, "Unauthorized", "%s", err)) // spent by a parallel call
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}
