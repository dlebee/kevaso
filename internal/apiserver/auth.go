package apiserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"time"

	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
)

// Auth turns on authentication. Without it (kevasod dev) every request is allowed, and the server
// must only listen on loopback.
//
// Who can do what until M4 brings RBAC:
//   - the local admin socket and user certificates with role cluster-admin: everything;
//   - hosts with role control-plane: everything (they run the controllers);
//   - hosts with role worker: read everything, write only their own Host's status and the status
//     of silos placed on them (they can't move a silo elsewhere);
//   - anyone without a certificate: only POST /enroll, with a join token.
type Auth struct {
	CA      *pki.CA
	Tokens  *jointoken.Issuer
	CertTTL time.Duration // client certificates' lifetime; default 30 days
}

type ctxKey int

const (
	adminConnKey ctxKey = iota
	identityKey
)

// LocalAdmin is the identity of whoever reaches the admin socket (root on the host).
var LocalAdmin = pki.Identity{Type: "user", Name: "root", Role: "cluster-admin"}

// IdentityFrom returns the authenticated identity of a request, if any.
func IdentityFrom(ctx context.Context) (pki.Identity, bool) {
	id, ok := ctx.Value(identityKey).(pki.Identity)
	return id, ok
}

func (s *Server) authenticate(r *http.Request) (pki.Identity, bool) {
	if admin, _ := r.Context().Value(adminConnKey).(bool); admin {
		return LocalAdmin, true
	}
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 { // verified against the cluster CA by TLS
		id, err := pki.IdentityOf(r.TLS.PeerCertificates[0])
		return id, err == nil
	}
	return pki.Identity{}, false
}

func authorize(id pki.Identity, r *http.Request, t target) bool {
	switch {
	case id.Role == "cluster-admin" && id.Type == "user":
		return true
	case id.Role == "control-plane" && id.Type == "host":
		return true
	case id.Role == "worker" && id.Type == "host":
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
		switch r.URL.Path {
		case "/healthz":
			next.ServeHTTP(w, r)
			return
		case "/enroll":
			s.enroll(w, r)
			return
		}
		id, ok := s.authenticate(r)
		if !ok {
			writeErr(w, errf(http.StatusUnauthorized, "Unauthorized", "a client certificate from this cluster is required"))
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), identityKey, id))
		if r.URL.Path == "/admin/certs" {
			s.issueUserCert(w, r, id)
			return
		}
		t, err := parsePath(r.URL.Path)
		if err == nil && !authorize(id, r, t) {
			writeErr(w, errf(http.StatusForbidden, "Forbidden", "%s may not %s %s", id, r.Method, r.URL.Path))
			return
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
