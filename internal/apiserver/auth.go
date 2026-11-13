package apiserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/audit"
	"kevaso.com/core/internal/issuer"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/rbac"
)

// Auth turns on authentication. Without it (kevasod dev) every request is allowed, and the server
// must only listen on loopback.
//
// Who can do what:
//   - the local admin socket: everything, whatever RBAC says (bootstrap and break-glass);
//   - people and service accounts: what RBAC grants them (see internal/rbac). User certificates
//     minted by kvoadm are in the cluster-admins group;
//   - hosts with role control-plane: everything (they run the controllers);
//   - hosts with role worker: read everything, write only their own Host's status and the status
//     of silos placed on them (they can't move a silo elsewhere);
//   - anyone without credentials: only POST /enroll, with a join token.
type Auth struct {
	CA      *pki.CA
	Tokens  *jointoken.Issuer
	CertTTL time.Duration // client certificates' lifetime; default 30 days
	// Issuer signs people in (kvo login) and verifies their bearer tokens. Optional.
	Issuer *issuer.Issuer
	// Audit records every decision about people and service accounts (and hosts' refusals).
	Audit audit.Sink
}

func (s *Server) record(r *http.Request, id pki.Identity, groups []string, a rbac.Attributes, allowed bool, reason string) {
	if s.auth == nil || s.auth.Audit == nil || ((id.Type == "host" || id.Type == "component") && allowed) {
		return // machines do the same narrow things all day; their refusals are what's interesting
	}
	s.auth.Audit.Record(audit.Entry{Time: s.clock.Now(), User: id.Name, Type: id.Type, Groups: groups, Verb: a.Verb,
		Resource: a.Resource, Namespace: a.Namespace, Name: a.Name, Allowed: allowed, Reason: reason, Remote: r.RemoteAddr})
}

type ctxKey int

const (
	adminConnKey ctxKey = iota
	componentConnKey
	identityKey
	groupsKey
	nsFilterKey
	secretFilterKey
)

// LocalAdmin is the identity of whoever reaches the admin socket (root on the host).
var LocalAdmin = pki.Identity{Type: "user", Name: "root", Role: "cluster-admin"}

// IdentityFrom returns the authenticated identity of a request, if any.
func IdentityFrom(ctx context.Context) (pki.Identity, bool) {
	id, ok := ctx.Value(identityKey).(pki.Identity)
	return id, ok
}

// authenticate finds who's calling: the admin socket, a client certificate, or a bearer token.
func (s *Server) authenticate(r *http.Request) (pki.Identity, []string, error) {
	if admin, _ := r.Context().Value(adminConnKey).(bool); admin {
		return LocalAdmin, groupsOf(LocalAdmin), nil
	}
	if c, _ := r.Context().Value(componentConnKey).(bool); c {
		return Component, nil, nil
	}
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 { // verified against the cluster CA by TLS
		id, err := pki.IdentityOf(r.TLS.PeerCertificates[0])
		return id, groupsOf(id), err
	}
	if raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		if s.auth.Issuer == nil {
			return pki.Identity{}, nil, errors.New("this cluster doesn't accept tokens")
		}
		c, err := s.auth.Issuer.Verify(r.Context(), raw)
		if err != nil {
			return pki.Identity{}, nil, fmt.Errorf("token: %w (run kvo login)", err)
		}
		typ := "user"
		if strings.HasPrefix(c.User, "system:serviceaccount:") {
			typ = "serviceaccount"
		}
		return pki.Identity{Type: typ, Name: c.User}, append([]string{rbac.Authenticated}, c.Groups...), nil
	}
	return pki.Identity{}, nil, errors.New("sign in with kvo login, or use a client certificate from this cluster")
}

// GroupsFrom returns the groups of a request's identity.
func GroupsFrom(ctx context.Context) []string {
	g, _ := ctx.Value(groupsKey).([]string)
	return g
}

// groupsOf: what a certificate identity is a member of.
func groupsOf(id pki.Identity) []string {
	g := []string{rbac.Authenticated}
	if id.Type == "user" && id.Role == "cluster-admin" {
		g = append(g, rbac.ClusterAdmins)
	}
	return g
}

// attributes turns a request into RBAC terms.
func attributes(id pki.Identity, groups []string, r *http.Request, t target) rbac.Attributes {
	a := rbac.Attributes{User: id.Name, Groups: groups, Resource: t.kind.Plural, Namespace: t.namespace, Name: t.name}
	if id.Type == "serviceaccount" {
		a.User = id.Name // already system:serviceaccount:NS:NAME
	}
	switch {
	case t.exec:
		a.Verb, a.Resource = "create", t.kind.Plural+"/exec"
	case t.stream == "files" && r.Method == http.MethodGet:
		a.Verb, a.Resource = "get", t.kind.Plural+"/files" // read, list, stat
	case t.stream != "":
		a.Verb, a.Resource = "create", t.kind.Plural+"/"+t.stream // ssh; files: write
	case t.move:
		a.Verb, a.Resource = "create", t.kind.Plural+"/move"
	case t.lease != "":
		a.Verb, a.Resource = v1.VerbOpen, v1.ResourceExposure // open and close
	case t.token:
		a.Verb, a.Resource = "create", t.kind.Plural+"/token"
	case t.value:
		a.Verb = "read-value"
	case t.answer != "":
		a.Verb, a.Resource = "create", t.kind.Plural+"/"+t.answer
	case t.bundle:
		a.Verb = "get" // the pane's own get: a bundle is part of what the pane shows
	case r.Method == http.MethodGet && t.name == "" && r.URL.Query().Get("watch") == "true":
		a.Verb = "watch"
	case r.Method == http.MethodGet && t.name == "":
		a.Verb = "list"
	case r.Method == http.MethodGet:
		a.Verb = "get"
	case r.Method == http.MethodPost:
		a.Verb = "create"
	case r.Method == http.MethodPut:
		a.Verb = "update"
	case r.Method == http.MethodPatch:
		a.Verb = "patch"
	case r.Method == http.MethodDelete:
		a.Verb = "delete"
	default:
		a.Verb = strings.ToLower(r.Method)
	}
	if t.status {
		a.Resource = t.kind.Plural + "/status"
	}
	return a
}

// authorizeRequest decides an API request. For people it asks RBAC; a person who may not list
// namespaces still gets the list, cut down to the ones they have a role in.
func (s *Server) authorizeRequest(ctx context.Context, id pki.Identity, groups []string, r *http.Request, t target) (allowed, filterNS bool, reason string, err error) {
	if id == LocalAdmin {
		return true, false, "local admin socket", nil
	}
	if id == Component {
		return true, false, "kevasod itself", nil
	}
	if id.Type == "host" {
		if hostAuthorize(id, r, t) {
			return true, false, "host " + id.Role, nil
		}
		return false, false, "hosts with role " + id.Role + " may not do this", nil
	}
	p, err := s.policy.Policy(ctx)
	if err != nil {
		return false, false, "", err
	}
	a := attributes(id, groups, r, t)
	a.Labels = s.secretLabels(ctx, t)
	if t.answer != "" {
		a = s.approvalAttributes(ctx, a, t)
	}
	if t.lease != "" {
		a = s.exposureAttributes(ctx, a, v1.VerbOpen, t.namespace, t.name)
	}
	d := p.Authorize(a)
	if !d.Allowed && t.kind.Kind == "Namespace" && a.Verb == "list" {
		return true, true, "namespaces you have a role in", nil
	}
	if !d.Allowed && t.kind.Kind == "Secret" && (a.Verb == "list" || a.Verb == "watch") && p.MaySelect(a) {
		return true, true, "secrets your roles name or select", nil
	}
	return d.Allowed, false, d.Reason, nil
}

func hostAuthorize(id pki.Identity, r *http.Request, t target) bool {
	switch {
	case t.value: // values reach hosts only for their own silos, through the broker
		return false
	case t.answer != "": // only people answer approvals
		return false
	case t.lease != "": // hosts never open leases (a silo asks through its broker)
		return false
	case t.bundle: // bundles are for people's clients, never for hosts
		return false
	case id.Role == "control-plane" && id.Type == "host":
		return true
	case id.Role == "worker" && id.Type == "host":
		if t.exec || t.token || t.move || t.stream != "" {
			return false
		}
		if r.Method == http.MethodGet {
			return true
		}
		if r.Method != http.MethodPut || !t.status {
			return false
		}
		// Its own Host's status; a Silo's status only if the silo is placed on it (checked in
		// update, which has the stored object).
		return (t.kind.Kind == "Host" && t.name == id.Name) || t.kind.Kind == "Silo"
	}
	return false
}

// wrap enforces authentication and authorization around the API, and serves /enroll and
// /admin/certs.
func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.auth == nil {
			next.ServeHTTP(w, r)
			return
		}
		switch {
		case r.URL.Path == "/healthz":
			next.ServeHTTP(w, r)
			return
		case r.URL.Path == "/enroll":
			s.enroll(w, r)
			return
		case r.URL.Path == "/ca.crt": // public: kvo login checks it against the fingerprint it was given
			w.Header().Set("Content-Type", "application/x-pem-file")
			_, _ = w.Write(s.auth.CA.PEM)
			return
		case s.auth.Issuer != nil && (r.URL.Path == issuer.PathDiscovery || strings.HasPrefix(r.URL.Path, "/oidc/")):
			s.auth.Issuer.Handler().ServeHTTP(w, r)
			return
		}
		id, groups, err := s.authenticate(r)
		if err != nil {
			if s.auth.Audit != nil {
				e := audit.Entry{Time: s.clock.Now(), Event: "authenticate", Verb: r.Method, Resource: r.URL.Path, Reason: err.Error(), Remote: r.RemoteAddr}
				if raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
					e.Claimed = issuer.ClaimedSubject(raw)
				}
				s.auth.Audit.Record(e)
			}
			writeErr(w, errf(http.StatusUnauthorized, "Unauthorized", "%s", err))
			return
		}
		ctx := context.WithValue(context.WithValue(r.Context(), identityKey, id), groupsKey, groups)
		r = r.WithContext(ctx)
		if r.URL.Path == "/admin/certs" {
			s.issueUserCert(w, r, id)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin/users") || r.URL.Path == "/admin/invites" || r.URL.Path == "/admin/join-tokens" {
			s.users(w, r, id, groups)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin/kms/") {
			s.kmsEndpoints(w, r, id)
			return
		}
		if r.URL.Path == "/admin/backup" {
			s.backupEndpoint(w, r, id)
			return
		}
		if r.URL.Path == "/auth/can-i" {
			s.canI(w, r, id, groups)
			return
		}
		if r.URL.Path == "/auth/whoami" {
			writeJSON(w, http.StatusOK, client.WhoAmI{Type: id.Type, Name: id.Name, Role: id.Role, Groups: groups})
			return
		}
		t, err := s.parseAny(ctx, r.URL.Path)
		if err == nil {
			ok, filter, reason, err := s.authorizeRequest(ctx, id, groups, r, t)
			if err != nil {
				writeErr(w, err)
				return
			}
			s.record(r, id, groups, attributes(id, groups, r, t), ok, reason)
			if !ok {
				writeErr(w, errf(http.StatusForbidden, "Forbidden", "%s: %s", id, reason))
				return
			}
			if filter && t.kind.Kind == "Secret" {
				r = r.WithContext(context.WithValue(ctx, secretFilterKey, true))
			} else if filter {
				r = r.WithContext(context.WithValue(ctx, nsFilterKey, true))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// CertRequest asks for a client certificate.
type CertRequest struct {
	Token string `json:"token,omitempty"` // /enroll only
	Host  string `json:"host,omitempty"`  // /enroll: the host joining
	Role  string `json:"role,omitempty"`  // /enroll: control-plane or worker
	Name  string `json:"name,omitempty"`  // /admin/certs: the user's name
	CSR   string `json:"csr"`             // PEM
}

// CertResponse returns the certificate and the CA to trust.
type CertResponse struct {
	Certificate string `json:"certificate"` // PEM
	CA          string `json:"ca"`          // PEM
}

func (s *Server) certTTL() time.Duration {
	if s.auth.CertTTL > 0 {
		return s.auth.CertTTL
	}
	return 30 * 24 * time.Hour
}

func decodeCertRequest(r *http.Request) (CertRequest, error) {
	var req CertRequest
	if r.Method != http.MethodPost {
		return req, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "use POST")
	}
	body, err := readBody(r)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errf(http.StatusBadRequest, "BadRequest", "body: %v", err)
	}
	return req, nil
}

// enroll: a host presents its join token and a CSR, and gets a certificate for that host and role.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	req, err := decodeCertRequest(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	id := pki.Identity{Type: "host", Name: req.Host, Role: req.Role}
	if err := id.Validate(); err != nil {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "%s", err))
		return
	}
	if err := s.auth.Tokens.Redeem(r.Context(), req.Token, req.Host, req.Role); err != nil {
		code := http.StatusUnauthorized
		if errors.Is(err, jointoken.ErrNotAllowed) {
			code = http.StatusForbidden
		}
		writeErr(w, errf(code, http.StatusText(code), "%s", err))
		return
	}
	s.signAndReply(w, []byte(req.CSR), id)
}

// issueUserCert: only through the admin socket (root on a control-plane host) can a user
// certificate be minted. That's how `kvoadm init` hands you credentials for `kvo`.
func (s *Server) issueUserCert(w http.ResponseWriter, r *http.Request, caller pki.Identity) {
	if caller != LocalAdmin {
		writeErr(w, errf(http.StatusForbidden, "Forbidden", "user certificates are issued only through the admin socket"))
		return
	}
	req, err := decodeCertRequest(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	id := pki.Identity{Type: "user", Name: req.Name, Role: "cluster-admin"}
	if err := id.Validate(); err != nil {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "%s", err))
		return
	}
	s.signAndReply(w, []byte(req.CSR), id)
}

func (s *Server) signAndReply(w http.ResponseWriter, csr []byte, id pki.Identity) {
	cert, err := s.auth.CA.SignCSR(csr, id, s.clock.Now(), s.certTTL())
	if err != nil {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "%s", err))
		return
	}
	writeJSON(w, http.StatusOK, CertResponse{Certificate: string(cert), CA: string(s.auth.CA.PEM)})
}

// TLSConfig is the API listener's TLS: TLS 1.3, client certificates verified against the cluster
// CA when presented (a client without one can only reach /enroll and /healthz).
func (s *Server) TLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    s.auth.CA.Pool(),
	}
}

// ListenAdminSocket opens the admin unix socket at path, readable and writable by its owner only.
func ListenAdminSocket(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// HTTPServer returns an http.Server for a listener. admin marks every connection on it as the
// local admin; use it only for the admin socket.
func (s *Server) HTTPServer(admin bool) *http.Server {
	return &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, adminConnKey, admin)
		},
	}
}
