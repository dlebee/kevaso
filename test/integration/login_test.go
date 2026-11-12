package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/audit"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/issuer"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/login"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/internal/tokenstore"
)

type cluster struct {
	url   string
	ca    []byte
	admin *client.Client
	iss   *issuer.Issuer
	audit *audit.Memory
	ctx   context.Context
}

// newCluster runs an API server with TLS from a private CA, the issuer, and the admin socket.
func newCluster(t *testing.T) *cluster {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	now := time.Now()
	ca, err := pki.NewCA("it", now)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	ts := httptestTLS(t)
	iss, err := issuer.New(ctx, st, clock.Real{}, ts.url)
	if err != nil {
		t.Fatal(err)
	}
	log := &audit.Memory{}
	iss.Audit = log
	srv, err := apiserver.NewWithAuth(st, clock.Real{}, &apiserver.Auth{CA: ca, Tokens: &jointoken.Issuer{Store: st, Clock: clock.Real{}}, Issuer: iss, Audit: log})
	if err != nil {
		t.Fatal(err)
	}
	localKMS, err := kms.OpenLocal(filepath.Join(t.TempDir(), "kms.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetVault(&secrets.Vault{Store: st, KMS: localKMS, Now: time.Now})
	srv.SetKMSAdmin(localKMS)
	sc, _ := ca.ServerCert([]string{"127.0.0.1"}, now, time.Hour)
	ts.start(t, srv, srv.TLSConfig(sc))

	dir, _ := os.MkdirTemp("/tmp", "kvi") // unix socket paths are short on macOS
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := apiserver.ListenAdminSocket(filepath.Join(dir, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	hs := srv.HTTPServer(true)
	go func() { _ = hs.Serve(l) }()
	t.Cleanup(func() { _ = hs.Close() })
	return &cluster{url: ts.url, ca: ca.PEM, admin: client.NewUnix(filepath.Join(dir, "admin.sock")), iss: iss, audit: log, ctx: ctx}
}

func (c *cluster) invite(t *testing.T, user string, groups ...string) string {
	t.Helper()
	var resp client.InviteResponse
	if err := c.admin.Call(c.ctx, http.MethodPost, "/admin/invites", client.InviteRequest{User: user, Groups: groups}, &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Code
}

// browser plays the person: open the page kvo shows, paste the code, submit.
func browser(t *testing.T, code string) func(string) error {
	return func(authURL string) error {
		jar, _ := cookiejar.New(nil)
		hc := &http.Client{Jar: jar}
		resp, err := hc.Get(authURL)
		if err != nil {
			return err
		}
		page, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(page), "Sign in to Kevaso") {
			return errors.New("no sign-in page")
		}
		u, _ := url.Parse(authURL)
		form := url.Values{"invite": {code}}
		for _, k := range []string{"redirect_uri", "state", "code_challenge", "nonce"} {
			form.Set(k, u.Query().Get(k))
		}
		// The form posts to the same origin: kvo's loopback relay. The redirect lands on its callback.
		resp, err = hc.PostForm("http://"+u.Host+issuer.PathLogin, form)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if !strings.Contains(string(body), "Signed in") {
			t.Errorf("after sign-in the browser shows: %d %s", resp.StatusCode, body)
		}
		return nil
	}
}

func ns(name string) *v1.Namespace {
	return &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: name}}
}

func silo(name, namespace string) *v1.Silo {
	return &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Image: "ubuntu-24.04", Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
}

// M4's "done when", in one process: a second user signs in with an invite and only sees their
// namespace.
func TestASecondUserOnlySeesTheirNamespace(t *testing.T) {
	c := newCluster(t)
	for _, n := range []string{"payments", "secret-project"} {
		if err := c.admin.Create(c.ctx, ns(n)); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.admin.Create(c.ctx, silo("ledger", "secret-project"))
	if err := c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "bob", Namespace: "payments"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"},
		Subjects: []v1.Subject{{Kind: "User", Name: "bob"}}}); err != nil {
		t.Fatal(err)
	}

	// Bob gets the server, the CA fingerprint and a code from the admin.
	fp, _ := client.Fingerprint(c.ca)
	if _, err := login.FetchCA(c.ctx, c.url, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("a wrong fingerprint was accepted")
	}
	caPEM, err := login.FetchCA(c.ctx, c.url, fp)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := login.Login(c.ctx, c.url, caPEM, login.Options{Open: browser(t, c.invite(t, "bob"))})
	if err != nil {
		t.Fatal(err)
	}
	st := tokenstore.File{Dir: t.TempDir()}
	if err := login.Save(st, "it", tok); err != nil {
		t.Fatal(err)
	}
	bob, _ := client.NewTLS(c.url, caPEM, nil, nil)
	bob.Token = login.Tokens(c.url, caPEM, st, "it", t.TempDir())

	if err := bob.Create(c.ctx, silo("api", "payments")); err != nil {
		t.Fatalf("bob creating in his namespace: %v", err)
	}
	var l []json.RawMessage
	if err := list(c.ctx, bob, "Silo", "payments", &l); err != nil || len(l) != 1 {
		t.Fatalf("bob listing his silos: %d, %v", len(l), err)
	}
	for what, err := range map[string]error{
		"list silos in secret-project": list(c.ctx, bob, "Silo", "secret-project", &l),
		"get a silo in secret-project": bob.Get(c.ctx, "Silo", "secret-project", "ledger", &v1.Silo{}),
		"list silos everywhere":        list(c.ctx, bob, "Silo", "", &l),
		"list hosts":                   list(c.ctx, bob, "Host", "", &l),
		"bind himself admin":           bob.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: "x", Namespace: "payments"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "admin"}, Subjects: []v1.Subject{{Kind: "User", Name: "bob"}}}),
		"invite someone":               bob.Call(c.ctx, http.MethodPost, "/admin/invites", client.InviteRequest{User: "eve"}, nil),
	} {
		var ce *client.Error
		if !errors.As(err, &ce) || ce.Code != http.StatusForbidden {
			t.Errorf("bob may not %s: got %v", what, err)
		}
	}
	if _, err := bob.List(c.ctx, "Silo", "secret-project"); err == nil || strings.Contains(err.Error(), "()") || !strings.Contains(err.Error(), "user:bob: no role lets bob") {
		t.Errorf("refusal reads %q", err)
	}
	// Listing namespaces shows only his.
	if err := list(c.ctx, bob, "Namespace", "", &l); err != nil || len(l) != 1 || !strings.Contains(string(l[0]), `"payments"`) {
		t.Fatalf("bob's namespaces: %d %v", len(l), err)
	}
	var can client.CanIResponse
	_ = bob.Call(c.ctx, http.MethodGet, "/auth/can-i?verb=create&resource=silos/exec&namespace=payments", nil, &can)
	if !can.Allowed || !strings.Contains(can.Reason, "RoleBinding payments/bob") {
		t.Fatalf("can-i: %+v", can)
	}

	// Everything bob did, or tried, is in the audit log, with the reason.
	find := func(pred func(audit.Entry) bool) bool {
		for _, e := range c.audit.Entries() {
			if pred(e) {
				return true
			}
		}
		return false
	}
	for what, pred := range map[string]func(audit.Entry) bool{
		"sign-in": func(e audit.Entry) bool { return e.Event == "sign-in" && e.User == "bob" && e.Allowed },
		"allowed": func(e audit.Entry) bool {
			return e.User == "bob" && e.Verb == "create" && e.Resource == "silos" && e.Allowed && strings.Contains(e.Reason, "bob")
		},
		"denied": func(e audit.Entry) bool {
			return e.User == "bob" && e.Verb == "list" && e.Namespace == "secret-project" && !e.Allowed
		},
		"denied admin": func(e audit.Entry) bool { return e.User == "bob" && e.Resource == "invites" && !e.Allowed },
		"admin socket": func(e audit.Entry) bool {
			return e.User == "root" && e.Resource == "namespaces" && e.Reason == "local admin socket"
		},
	} {
		if !find(pred) {
			t.Errorf("audit log has no %s entry", what)
		}
	}

	// Disabling bob ends it at once.
	if err := c.admin.Call(c.ctx, http.MethodPost, "/admin/users/bob/disable", nil, nil); err != nil {
		t.Fatal(err)
	}
	var ce *client.Error
	if err := list(c.ctx, bob, "Silo", "payments", &l); !errors.As(err, &ce) || ce.Code != http.StatusUnauthorized {
		t.Fatalf("bob after disable: %v", err)
	}
	if !find(func(e audit.Entry) bool { return e.Event == "disable" && e.User == "bob" }) ||
		!find(func(e audit.Entry) bool {
			return e.Event == "authenticate" && !e.Allowed && strings.Contains(e.Reason, "session ended") && e.Claimed == "bob" && e.User == ""
		}) {
		t.Error("audit log is missing the disable or the refused token")
	}
}

// Access tokens are short; kvo refreshes them, saving each rotated refresh token.
func TestTokensRefreshAndRotate(t *testing.T) {
	c := newCluster(t)
	c.iss.AccessTTL = time.Second // always "about to expire": every call refreshes
	_ = c.admin.Create(c.ctx, ns("payments"))
	tok, err := login.Login(c.ctx, c.url, c.ca, login.Options{Open: browser(t, c.invite(t, "bob", "kevaso:cluster-admins"))})
	if err != nil {
		t.Fatal(err)
	}
	st := tokenstore.File{Dir: t.TempDir()}
	_ = login.Save(st, "it", tok)
	lock := t.TempDir()
	var last string
	for i := 0; i < 3; i++ {
		// A new client each time, like separate kvo commands.
		bob, _ := client.NewTLS(c.url, c.ca, nil, nil)
		bob.Token = login.Tokens(c.url, c.ca, st, "it", lock)
		if err := bob.Get(c.ctx, "Namespace", "", "payments", &v1.Namespace{}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		b, _ := st.Get("it")
		if string(b) == last {
			t.Fatalf("call %d: the refresh token didn't rotate", i)
		}
		last = string(b)
	}
}

func list(ctx context.Context, c *client.Client, kind, namespace string, out *[]json.RawMessage) error {
	l, err := c.List(ctx, kind, namespace)
	if err == nil {
		*out = l.Items
	}
	return err
}

type tlsServer struct {
	ts  *httptest.Server
	url string
}

// httptestTLS reserves the address first: the issuer needs its URL before the server starts.
func httptestTLS(t *testing.T) *tlsServer {
	ts := httptest.NewUnstartedServer(nil)
	return &tlsServer{ts: ts, url: "https://" + ts.Listener.Addr().String()}
}

func (s *tlsServer) start(t *testing.T, h http.Handler, cfg *tls.Config) {
	s.ts.Config.Handler = h
	s.ts.TLS = cfg
	s.ts.StartTLS()
	t.Cleanup(s.ts.Close)
}

func clientKeyCSR(t *testing.T) (key, csr []byte, err error) {
	t.Helper()
	return client.NewKeyAndCSR("david")
}

// Exposing a silo publicly is its own permission: an editor can't, an admin of the namespace can.
func TestExposePublicNeedsItsOwnPermission(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	bind := func(user, role string) {
		if err := c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
			ObjectMeta: meta.ObjectMeta{Name: user, Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: role},
			Subjects: []v1.Subject{{Kind: "User", Name: user}}}); err != nil {
			t.Fatal(err)
		}
	}
	bind("ed", "editor")
	bind("ada", "admin")
	as := func(user string) *client.Client {
		tok, err := login.Login(c.ctx, c.url, c.ca, login.Options{Open: browser(t, c.invite(t, user))})
		if err != nil {
			t.Fatal(err)
		}
		cl, _ := client.NewTLS(c.url, c.ca, nil, nil)
		cl.Token = func(context.Context) (string, error) { return tok.AccessToken, nil }
		return cl
	}
	node := func(name string) *v1.Silo {
		s := silo(name, "web3")
		s.Spec.Service = &v1.Service{Ports: []v1.ServicePort{{Name: "p2p", Port: 30303}}, Expose: v1.ExposeHostPort}
		return s
	}
	ed, ada := as("ed"), as("ada")
	err := ed.Create(c.ctx, node("by-ed"))
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Code != http.StatusForbidden || !strings.Contains(err.Error(), "services/expose-public") {
		t.Fatalf("editor exposing: %v", err)
	}
	private := silo("private", "web3")
	private.Spec.Service = &v1.Service{Ports: []v1.ServicePort{{Name: "http", Port: 8080}}}
	if err := ed.Create(c.ctx, private); err != nil {
		t.Fatalf("editor, private service: %v", err)
	}
	if err := ada.Create(c.ctx, node("by-ada")); err != nil {
		t.Fatalf("admin exposing: %v", err)
	}
	// The editor can still change other things on the exposed silo.
	var s v1.Silo
	_ = ed.Get(c.ctx, "Silo", "web3", "by-ada", &s)
	s.Spec.Resources.CPU = 2
	if err := ed.Update(c.ctx, &s); err != nil {
		t.Fatalf("editor updating an already-exposed silo: %v", err)
	}
}
