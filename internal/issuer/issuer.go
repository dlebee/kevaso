// Package issuer makes the control plane an OAuth2 / OIDC issuer (design §9.1, research E022).
// People sign in through `kvo login`: authorization code + PKCE (S256) with a loopback redirect,
// and, until upstream providers (GitHub, Google) exist, a one-time invite code from an admin on the
// login page. They get a short-lived access token (a JWT the API server verifies) and a refresh
// token that rotates on every use; presenting an old one again revokes the session.
package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// ClientID is kvo's: a public client (no secret), loopback redirects only.
const ClientID = "kvo"

// Audience of access tokens: the Kevaso API.
const Audience = "kevaso"

// raceGrace: a just-replaced refresh token coming back this soon is a race between two local
// commands, not theft.
const raceGrace = 10 * time.Second

var loopback = regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]{1,5}/callback$`)

// Paths, under the API server.
const (
	PathDiscovery = "/.well-known/openid-configuration"
	PathKeys      = "/oidc/keys"
	PathAuthorize = "/oidc/authorize"
	PathLogin     = "/oidc/login"
	PathToken     = "/oidc/token"
)

// Issuer issues and verifies tokens.
type Issuer struct {
	Store      store.Store
	Clock      clock.Clock
	URL        string        // the iss claim, e.g. https://203.0.113.10:6443
	AccessTTL  time.Duration // default 15 minutes
	SessionTTL time.Duration // idle limit of a refresh token; default 30 days

	key *ecdsa.PrivateKey
	kid string

	mu    sync.Mutex
	codes map[string]authCode
}

type authCode struct {
	user, redirect, challenge, nonce string
	expires                          time.Time
}

// Claims is what an access token says.
type Claims struct {
	User      string
	Groups    []string
	SessionID string
}

type tokenClaims struct {
	jwt.Claims
	Groups []string `json:"groups,omitempty"`
	SID    string   `json:"sid,omitempty"`
	Nonce  string   `json:"nonce,omitempty"`
}

// New loads (or creates) the signing key.
func New(ctx context.Context, st store.Store, clk clock.Clock, url string) (*Issuer, error) {
	k, kid, err := loadKey(ctx, st)
	if err != nil {
		return nil, err
	}
	return &Issuer{Store: st, Clock: clk, URL: strings.TrimRight(url, "/"), key: k, kid: kid, codes: map[string]authCode{}}, nil
}

func (i *Issuer) accessTTL() time.Duration {
	if i.AccessTTL > 0 {
		return i.AccessTTL
	}
	return 15 * time.Minute
}

func (i *Issuer) sessionTTL() time.Duration {
	if i.SessionTTL > 0 {
		return i.SessionTTL
	}
	return 30 * 24 * time.Hour
}

// ── users and invites ────────────────────────────────────────────────────────

var validName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.@_]*[a-z0-9])?$`)

// Invite returns a one-time code with which user signs in once (and gets a session). It creates
// the user, or re-enables them; groups, if given, replace theirs.
func (i *Issuer) Invite(ctx context.Context, user string, groups []string, ttl time.Duration) (string, time.Time, error) {
	if !validName.MatchString(user) || strings.HasPrefix(user, "system:") {
		return "", time.Time{}, fmt.Errorf("invalid user name %q", user)
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if err := i.upsertUser(ctx, user, groups); err != nil {
		return "", time.Time{}, err
	}
	id, secret := random(6), random(16)
	exp := i.Clock.Now().Add(ttl)
	data, _ := json.Marshal(invite{SecretHash: hash(secret), User: user, Expires: exp})
	if _, err := i.Store.Create(ctx, store.Key{Kind: KindInvite, Name: id}, data); err != nil {
		return "", time.Time{}, err
	}
	return "kvi_" + id + "." + secret, exp, nil
}

func (i *Issuer) upsertUser(ctx context.Context, name string, groups []string) error {
	key := store.Key{Kind: KindUser, Name: name}
	for attempt := 0; attempt < 5; attempt++ {
		var u User
		rev, err := getJSON(ctx, i.Store, key, &u)
		switch {
		case errors.Is(err, store.ErrNotFound):
			data, _ := json.Marshal(User{Name: name, Groups: groups, Created: i.Clock.Now()})
			if _, err := i.Store.Create(ctx, key, data); errors.Is(err, store.ErrExists) {
				continue
			} else {
				return err
			}
		case err != nil:
			return err
		}
		u.Disabled = false
		if groups != nil {
			u.Groups = groups
		}
		data, _ := json.Marshal(u)
		if _, err := i.Store.Update(ctx, key, data, rev); errors.Is(err, store.ErrConflict) {
			continue
		} else {
			return err
		}
	}
	return errors.New("user kept changing")
}

// Users lists everyone who can (or could) sign in.
func (i *Issuer) Users(ctx context.Context) ([]User, error) {
	objs, _, err := i.Store.List(ctx, store.Selector{Kind: KindUser})
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(objs))
	for _, o := range objs {
		var u User
		if err := json.Unmarshal(o.Data, &u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// Disable stops a user: their sessions end now, their access tokens stop working now.
func (i *Issuer) Disable(ctx context.Context, name string) error {
	key := store.Key{Kind: KindUser, Name: name}
	var u User
	rev, err := getJSON(ctx, i.Store, key, &u)
	if err != nil {
		return err
	}
	u.Disabled = true
	data, _ := json.Marshal(u)
	if _, err := i.Store.Update(ctx, key, data, rev); err != nil {
		return err
	}
	sessions, _, err := i.Store.List(ctx, store.Selector{Kind: KindSession})
	if err != nil {
		return err
	}
	for _, o := range sessions {
		var s session
		if json.Unmarshal(o.Data, &s) == nil && s.User == name {
			_, _ = i.Store.Delete(ctx, o.Key, 0)
		}
	}
	return nil
}

// redeemInvite uses an invite once and returns its user.
func (i *Issuer) redeemInvite(ctx context.Context, code string) (string, error) {
	bad := errors.New("that invite code isn't valid, was already used, or has expired")
	id, secret, ok := split(strings.TrimSpace(code), "kvi_")
	if !ok {
		return "", bad
	}
	key := store.Key{Kind: KindInvite, Name: id}
	for attempt := 0; attempt < 5; attempt++ {
		var inv invite
		rev, err := getJSON(ctx, i.Store, key, &inv)
		if err != nil {
			return "", bad
		}
		if !sameHash(secret, inv.SecretHash) || !inv.UsedAt.IsZero() || !i.Clock.Now().Before(inv.Expires) {
			return "", bad
		}
		inv.UsedAt = i.Clock.Now()
		data, _ := json.Marshal(inv)
		if _, err := i.Store.Update(ctx, key, data, rev); errors.Is(err, store.ErrConflict) {
			continue
		} else if err != nil {
			return "", err
		}
		return inv.User, nil
	}
	return "", bad
}

func (i *Issuer) user(ctx context.Context, name string) (User, error) {
	var u User
	_, err := getJSON(ctx, i.Store, store.Key{Kind: KindUser, Name: name}, &u)
	if err == nil && u.Disabled {
		err = errors.New("user is disabled")
	}
	return u, err
}

// ── tokens ───────────────────────────────────────────────────────────────────

func (i *Issuer) sign(c tokenClaims) (string, error) {
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", i.kid)
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: i.key}, opts)
	if err != nil {
		return "", err
	}
	return jwt.Signed(s).Claims(c).Serialize()
}

// TokenResponse is the token endpoint's answer.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

func (i *Issuer) tokens(u User, sid, refresh, nonce string) (TokenResponse, error) {
	now := i.Clock.Now()
	std := jwt.Claims{Issuer: i.URL, Subject: u.Name, IssuedAt: jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)), Expiry: jwt.NewNumericDate(now.Add(i.accessTTL()))}
	access := std
	access.Audience = jwt.Audience{Audience}
	at, err := i.sign(tokenClaims{Claims: access, Groups: u.Groups, SID: sid})
	if err != nil {
		return TokenResponse{}, err
	}
	id := std
	id.Audience = jwt.Audience{ClientID}
	it, err := i.sign(tokenClaims{Claims: id, Groups: u.Groups, Nonce: nonce})
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: at, TokenType: "Bearer", ExpiresIn: int(i.accessTTL().Seconds()), RefreshToken: refresh, IDToken: it}, nil
}

// Verify checks an access token: signature, issuer, audience, expiry, and that its session and
// user are still live (so disabling someone takes effect at once).
func (i *Issuer) Verify(ctx context.Context, raw string) (Claims, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return Claims{}, err
	}
	var c tokenClaims
	if err := tok.Claims(&i.key.PublicKey, &c); err != nil {
		return Claims{}, err
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Issuer: i.URL, AnyAudience: jwt.Audience{Audience}, Time: i.Clock.Now()}, 30*time.Second); err != nil {
		return Claims{}, err
	}
	if c.SID == "" {
		return Claims{}, errors.New("not an access token")
	}
	if _, err := i.Store.Get(ctx, store.Key{Kind: KindSession, Name: c.SID}); err != nil {
		return Claims{}, errors.New("session ended")
	}
	if _, err := i.user(ctx, c.Subject); err != nil {
		return Claims{}, err
	}
	return Claims{User: c.Subject, Groups: c.Groups, SessionID: c.SID}, nil
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

// Handler serves discovery, keys, the login page and the token endpoint.
func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(PathDiscovery, i.discovery)
	mux.HandleFunc(PathKeys, i.keys)
	mux.HandleFunc(PathAuthorize, i.authorize)
	mux.HandleFunc(PathLogin, i.login)
	mux.HandleFunc(PathToken, i.token)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (i *Issuer) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                i.URL,
		"authorization_endpoint":                i.URL + PathAuthorize,
		"token_endpoint":                        i.URL + PathToken,
		"jwks_uri":                              i.URL + PathKeys,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"openid", "offline_access", "groups"},
		"claims_supported":                      []string{"sub", "groups", "sid"},
	})
}

func (i *Issuer) keys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &i.key.PublicKey, KeyID: i.kid, Algorithm: "ES256", Use: "sig"}}})
}

// authRequest is what /authorize gets, and the login form carries along.
type authRequest struct {
	Redirect, State, Challenge, Nonce string
}

func parseAuthRequest(q url.Values) (authRequest, error) {
	switch {
	case q.Get("client_id") != ClientID:
		return authRequest{}, errors.New("unknown client_id")
	case !loopback.MatchString(q.Get("redirect_uri")):
		return authRequest{}, errors.New("redirect_uri must be http://127.0.0.1:<port>/callback")
	case q.Get("response_type") != "code":
		return authRequest{}, errors.New("response_type must be code")
	case q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43:
		return authRequest{}, errors.New("PKCE with S256 is required")
	case q.Get("state") == "":
		return authRequest{}, errors.New("state is required")
	}
	return authRequest{Redirect: q.Get("redirect_uri"), State: q.Get("state"), Challenge: q.Get("code_challenge"), Nonce: q.Get("nonce")}, nil
}

var page = template.Must(template.New("login").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to Kevaso</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;background:#0f1115;color:#e8e8ea;display:grid;place-items:center;min-height:100vh;margin:0}
main{width:min(380px,90vw)}h1{font-size:20px;margin:0 0 4px}p{color:#9a9aa3;margin:0 0 20px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #33343b;background:#17191f;color:inherit;font:15px ui-monospace,monospace}
button{margin-top:12px;width:100%;padding:10px;border:0;border-radius:8px;background:#e8e8ea;color:#0f1115;font-weight:600;font-size:15px;cursor:pointer}
.err{color:#ff8a80;margin:12px 0 0}
</style></head><body><main>
<h1>Sign in to Kevaso</h1>
<p>Paste the invite code your admin gave you.</p>
<form method="post" action="` + PathLogin + `">
<input type="hidden" name="redirect_uri" value="{{.Req.Redirect}}">
<input type="hidden" name="state" value="{{.Req.State}}">
<input type="hidden" name="code_challenge" value="{{.Req.Challenge}}">
<input type="hidden" name="nonce" value="{{.Req.Nonce}}">
<input name="invite" placeholder="kvi_…" autocomplete="off" autofocus required>
<button type="submit">Sign in</button>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
</form></main></body></html>`))

func showPage(w http.ResponseWriter, code int, req authRequest, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(code)
	_ = page.Execute(w, struct {
		Req   authRequest
		Error string
	}{req, msg})
}

func (i *Issuer) authorize(w http.ResponseWriter, r *http.Request) {
	req, err := parseAuthRequest(r.URL.Query())
	if err != nil {
		http.Error(w, "authorize: "+err.Error(), http.StatusBadRequest) // never redirect a bad request
		return
	}
	showPage(w, http.StatusOK, req, "")
}

func (i *Issuer) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	f.Set("client_id", ClientID)
	f.Set("response_type", "code")
	f.Set("code_challenge_method", "S256")
	req, err := parseAuthRequest(f)
	if err != nil {
		http.Error(w, "login: "+err.Error(), http.StatusBadRequest)
		return
	}
	user, err := i.redeemInvite(r.Context(), f.Get("invite"))
	if err == nil {
		_, err = i.user(r.Context(), user)
	}
	if err != nil {
		showPage(w, http.StatusUnauthorized, req, err.Error())
		return
	}
	code := random(24)
	i.mu.Lock()
	now := i.Clock.Now()
	for c, ac := range i.codes { // drop expired ones
		if now.After(ac.expires) {
			delete(i.codes, c)
		}
	}
	i.codes[code] = authCode{user: user, redirect: req.Redirect, challenge: req.Challenge, nonce: req.Nonce, expires: now.Add(time.Minute)}
	i.mu.Unlock()
	u, _ := url.Parse(req.Redirect)
	q := u.Query()
	q.Set("code", code)
	q.Set("state", req.State)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func tokenErr(w http.ResponseWriter, code int, e, desc string) {
	writeJSON(w, code, map[string]string{"error": e, "error_description": desc})
}

func (i *Issuer) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tokenErr(w, http.StatusMethodNotAllowed, "invalid_request", "POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		tokenErr(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	f := r.PostForm
	// A public client: client_id in the form or as basic auth with an empty secret (research E022:
	// libraries probe both; accept either, and check everything before a code is used up).
	client := f.Get("client_id")
	if u, _, ok := r.BasicAuth(); ok && client == "" {
		client = u
	}
	if client != ClientID {
		tokenErr(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	switch f.Get("grant_type") {
	case "authorization_code":
		i.exchange(w, r.Context(), f)
	case "refresh_token":
		i.refresh(w, r.Context(), f.Get("refresh_token"))
	default:
		tokenErr(w, http.StatusBadRequest, "unsupported_grant_type", "authorization_code or refresh_token")
	}
}

func (i *Issuer) exchange(w http.ResponseWriter, ctx context.Context, f url.Values) {
	code, redirect, verifier := f.Get("code"), f.Get("redirect_uri"), f.Get("code_verifier")
	if code == "" || redirect == "" || len(verifier) < 43 {
		tokenErr(w, http.StatusBadRequest, "invalid_request", "code, redirect_uri and code_verifier are required")
		return
	}
	i.mu.Lock()
	ac, ok := i.codes[code]
	delete(i.codes, code) // single use: burnt on first well-formed presentation
	i.mu.Unlock()
	if !ok || i.Clock.Now().After(ac.expires) {
		tokenErr(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired code")
		return
	}
	if ac.redirect != redirect {
		tokenErr(w, http.StatusBadRequest, "invalid_grant", "redirect_uri doesn't match")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != ac.challenge {
		tokenErr(w, http.StatusBadRequest, "invalid_grant", "PKCE verifier does not match")
		return
	}
	u, err := i.user(ctx, ac.user)
	if err != nil {
		tokenErr(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	sid, secret := random(12), random(32)
	now := i.Clock.Now()
	data, _ := json.Marshal(session{User: u.Name, RefreshHash: hash(secret), Expires: now.Add(i.sessionTTL()), Created: now})
	if _, err := i.Store.Create(ctx, store.Key{Kind: KindSession, Name: sid}, data); err != nil {
		tokenErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	resp, err := i.tokens(u, sid, "kvr_"+sid+"."+secret, ac.nonce)
	if err != nil {
		tokenErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (i *Issuer) refresh(w http.ResponseWriter, ctx context.Context, tok string) {
	bad := func(msg string) { tokenErr(w, http.StatusBadRequest, "invalid_grant", msg) }
	sid, secret, ok := split(tok, "kvr_")
	if !ok {
		bad("malformed refresh token")
		return
	}
	key := store.Key{Kind: KindSession, Name: sid}
	var s session
	rev, err := getJSON(ctx, i.Store, key, &s)
	if err != nil {
		bad("session ended; run kvo login again")
		return
	}
	now := i.Clock.Now()
	switch {
	case s.PrevHash != "" && sameHash(secret, s.PrevHash) && now.Sub(s.RotatedAt) < raceGrace:
		// Two kvo commands refreshed at once; the other one won. The client re-reads its token.
		bad("refresh raced with another; try again")
		return
	case s.PrevHash != "" && sameHash(secret, s.PrevHash):
		// An old refresh token came back: someone else has a copy. End the session for everyone.
		_, _ = i.Store.Delete(ctx, key, 0)
		bad("refresh token was already used; session revoked")
		return
	case !sameHash(secret, s.RefreshHash) || !now.Before(s.Expires):
		bad("session ended; run kvo login again")
		return
	}
	u, err := i.user(ctx, s.User)
	if err != nil {
		bad(err.Error())
		return
	}
	next := random(32)
	s.PrevHash, s.RefreshHash, s.Expires, s.RotatedAt = s.RefreshHash, hash(next), now.Add(i.sessionTTL()), now
	data, _ := json.Marshal(s)
	if _, err := i.Store.Update(ctx, key, data, rev); err != nil {
		bad("refresh raced with another; try again") // two refreshes at once: one wins
		return
	}
	resp, err := i.tokens(u, sid, "kvr_"+sid+"."+next, "")
	if err != nil {
		tokenErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
