package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/rbac"
)

// can asks RBAC about a non-resource action (the admin socket may do anything; hosts nothing).
func (s *Server) can(ctx context.Context, id pki.Identity, groups []string, a rbac.Attributes) (rbac.Decision, error) {
	if id == LocalAdmin {
		return rbac.Decision{Allowed: true, Reason: "local admin socket"}, nil
	}
	if id.Type == "host" {
		return rbac.Decision{Reason: "hosts may not manage users"}, nil
	}
	p, err := s.policy.Policy(ctx)
	if err != nil {
		return rbac.Decision{}, err
	}
	a.User, a.Groups = id.Name, groups
	return p.Authorize(a), nil
}

// users serves /admin/invites, GET /admin/users and POST /admin/users/NAME/disable. RBAC: create
// invites, list users, update users (cluster-admin has them all).
func (s *Server) users(w http.ResponseWriter, r *http.Request, id pki.Identity, groups []string) {
	iss := s.auth.Issuer
	if iss == nil {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "this cluster has no issuer"))
		return
	}
	var a rbac.Attributes
	var name string
	switch {
	case r.URL.Path == "/admin/invites" && r.Method == http.MethodPost:
		a = rbac.Attributes{Verb: "create", Resource: "invites"}
	case r.URL.Path == "/admin/users" && r.Method == http.MethodGet:
		a = rbac.Attributes{Verb: "list", Resource: "users"}
	case strings.HasSuffix(r.URL.Path, "/disable") && r.Method == http.MethodPost:
		name = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/users/"), "/disable")
		a = rbac.Attributes{Verb: "update", Resource: "users", Name: name}
	default:
		writeErr(w, errf(http.StatusNotFound, "NotFound", "%s %s", r.Method, r.URL.Path))
		return
	}
	d, err := s.can(r.Context(), id, groups, a)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !d.Allowed {
		writeErr(w, errf(http.StatusForbidden, "Forbidden", "%s: %s", id, d.Reason))
		return
	}
	switch a.Resource + "/" + a.Verb {
	case "invites/create":
		body, err := readBody(r)
		if err != nil {
			writeErr(w, err)
			return
		}
		var req client.InviteRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(w, errf(http.StatusBadRequest, "BadRequest", "%s", err))
			return
		}
		var ttl time.Duration
		if req.TTL != "" {
			if ttl, err = time.ParseDuration(req.TTL); err != nil || ttl <= 0 || ttl > 7*24*time.Hour {
				writeErr(w, errf(http.StatusBadRequest, "BadRequest", "ttl must be a duration up to 168h"))
				return
			}
		}
		code, exp, err := iss.Invite(r.Context(), req.User, req.Groups, ttl)
		if err != nil {
			writeErr(w, errf(http.StatusBadRequest, "BadRequest", "%s", err))
			return
		}
		fp, _ := client.Fingerprint(s.auth.CA.PEM)
		writeJSON(w, http.StatusOK, client.InviteResponse{User: req.User, Code: code, Expires: exp, CAFingerprint: fp})
	case "users/list":
		us, err := iss.Users(r.Context())
		if err != nil {
			writeErr(w, err)
			return
		}
		out := make([]client.User, 0, len(us))
		for _, u := range us {
			out = append(out, client.User(u))
		}
		writeJSON(w, http.StatusOK, map[string][]client.User{"items": out})
	case "users/update":
		if err := iss.Disable(r.Context(), name); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"user": name, "status": "disabled"})
	}
}

// canI answers whether the caller may do something: GET /auth/can-i?verb=&resource=&namespace=&name=
func (s *Server) canI(w http.ResponseWriter, r *http.Request, id pki.Identity, groups []string) {
	q := r.URL.Query()
	a := rbac.Attributes{Verb: q.Get("verb"), Resource: q.Get("resource"), Namespace: q.Get("namespace"), Name: q.Get("name")}
	if a.Verb == "" || a.Resource == "" {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "verb and resource are required"))
		return
	}
	var d rbac.Decision
	var err error
	if id.Type == "host" {
		d = rbac.Decision{Reason: "hosts aren't governed by RBAC"}
	} else {
		d, err = s.can(r.Context(), id, groups, a)
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, client.CanIResponse{Allowed: d.Allowed, Reason: d.Reason})
}
