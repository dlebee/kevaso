package issuer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

type env struct {
	iss *Issuer
	ts  *httptest.Server
	clk *clock.Fake
	ctx context.Context
}

func setup(t *testing.T) *env {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	clk := clock.NewFake(time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC))
	st := store.NewMemory(0)
	ts := httptest.NewServer(nil)
	t.Cleanup(ts.Close)
	iss, err := New(ctx, st, clk, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = iss.Handler()
	return &env{iss: iss, ts: ts, clk: clk, ctx: ctx}
}

func (e *env) config(style oauth2.AuthStyle) *oauth2.Config {
	return &oauth2.Config{ClientID: ClientID, RedirectURL: "http://127.0.0.1:41234/callback", Scopes: []string{"openid", "offline_access"},
		Endpoint: oauth2.Endpoint{AuthURL: e.ts.URL + PathAuthorize, TokenURL: e.ts.URL + PathToken, AuthStyle: style}}
}

// browse plays the browser: open the authorize URL, submit the invite, and return the redirect.
func (e *env) browse(t *testing.T, authURL, invite string) (*http.Response, string) {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp, ""
	}
	u, _ := url.Parse(authURL)
	form := url.Values{"invite": {invite}}
	for _, k := range []string{"redirect_uri", "state", "code_challenge", "nonce"} {
		form.Set(k, u.Query().Get(k))
	}
	resp, err = c.PostForm(e.ts.URL+PathLogin, form)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp, resp.Header.Get("Location")
}

// login runs the whole kvo login flow and returns the tokens.
func (e *env) login(t *testing.T, cfg *oauth2.Config, invite string) *oauth2.Token {
	t.Helper()
	verifier := oauth2.GenerateVerifier()
	resp, loc := e.browse(t, cfg.AuthCodeURL("st4te", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", "n0nce")), invite)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	cb, _ := url.Parse(loc)
	if !strings.HasPrefix(loc, cfg.RedirectURL) || cb.Query().Get("state") != "st4te" {
		t.Fatalf("callback %q", loc)
	}
	tok, err := cfg.Exchange(e.ctx, cb.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestLoginWithAnInvite(t *testing.T) {
	e := setup(t)
	code, _, err := e.iss.Invite(e.ctx, "bob", []string{"team-payments"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, style := range []oauth2.AuthStyle{oauth2.AuthStyleInParams, oauth2.AuthStyleInHeader, oauth2.AuthStyleAutoDetect} {
		tok := e.login(t, e.config(style), code)
		c, err := e.iss.Verify(e.ctx, tok.AccessToken)
		if err != nil || c.User != "bob" || len(c.Groups) != 1 || c.Groups[0] != "team-payments" {
			t.Fatalf("style %d: %+v, %v", style, c, err)
		}
		if !strings.HasPrefix(tok.RefreshToken, "kvr_") || tok.Extra("id_token") == nil {
			t.Fatalf("tokens: %+v", tok)
		}
		code, _, _ = e.iss.Invite(e.ctx, "bob", nil, 0) // each login needs its own code; groups kept
	}
}

func TestRefusals(t *testing.T) {
	e := setup(t)
	cfg := e.config(oauth2.AuthStyleInParams)
	code, _, _ := e.iss.Invite(e.ctx, "bob", nil, time.Minute)

	// A redirect that isn't loopback, or no PKCE: the page isn't even shown.
	bad := cfg.AuthCodeURL("s", oauth2.S256ChallengeOption(oauth2.GenerateVerifier()))
	for name, u := range map[string]string{
		"evil redirect": strings.Replace(bad, url.QueryEscape("http://127.0.0.1:41234/callback"), url.QueryEscape("https://evil.example/callback"), 1),
		"localhost":     strings.Replace(bad, url.QueryEscape("http://127.0.0.1:41234/callback"), url.QueryEscape("http://localhost:41234/callback"), 1),
		"other path":    strings.Replace(bad, url.QueryEscape("http://127.0.0.1:41234/callback"), url.QueryEscape("http://127.0.0.1:41234/steal"), 1),
		"no PKCE":       cfg.AuthCodeURL("s"),
		"other client":  strings.Replace(bad, "client_id=kvo", "client_id=evil", 1),
	} {
		if resp, _ := e.browse(t, u, code); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	// A wrong invite code shows the page again; no code is issued.
	if resp, loc := e.browse(t, bad, "kvi_nope.nope"); resp.StatusCode != http.StatusUnauthorized || loc != "" {
		t.Errorf("wrong invite: %d %q", resp.StatusCode, loc)
	}

	// A wrong PKCE verifier, then the same code again.
	resp, loc := e.browse(t, cfg.AuthCodeURL("s", oauth2.S256ChallengeOption(oauth2.GenerateVerifier())), code)
	if resp.StatusCode != http.StatusFound {
		t.Fatal(resp.StatusCode)
	}
	cb, _ := url.Parse(loc)
	if _, err := cfg.Exchange(e.ctx, cb.Query().Get("code"), oauth2.VerifierOption(oauth2.GenerateVerifier())); err == nil || !strings.Contains(err.Error(), "PKCE") {
		t.Errorf("wrong verifier: %v", err)
	}
	if _, err := cfg.Exchange(e.ctx, cb.Query().Get("code"), oauth2.VerifierOption(oauth2.GenerateVerifier())); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("code reuse: %v", err)
	}
	// The invite is used up.
	if resp, _ := e.browse(t, bad, code); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("invite reuse: %d", resp.StatusCode)
	}
	// An expired invite.
	late, _, _ := e.iss.Invite(e.ctx, "carol", nil, time.Minute)
	e.clk.Step(2 * time.Minute)
	if resp, _ := e.browse(t, bad, late); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expired invite: %d", resp.StatusCode)
	}
	if _, _, err := e.iss.Invite(e.ctx, "system:root", nil, 0); err == nil {
		t.Error("a system: user was invited")
	}
}

func TestAccessTokens(t *testing.T) {
	e := setup(t)
	code, _, _ := e.iss.Invite(e.ctx, "bob", nil, 0)
	tok := e.login(t, e.config(oauth2.AuthStyleInParams), code)
	e.clk.Step(16 * time.Minute)
	if _, err := e.iss.Verify(e.ctx, tok.AccessToken); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired access token: %v", err)
	}
	if _, err := e.iss.Verify(e.ctx, tok.Extra("id_token").(string)); err == nil {
		t.Error("an ID token was accepted as an access token")
	}
	// Another cluster's issuer signs with another key.
	other := setup(t)
	oc, _, _ := other.iss.Invite(other.ctx, "bob", nil, 0)
	ot := other.login(t, other.config(oauth2.AuthStyleInParams), oc)
	other.iss.URL = e.iss.URL // even claiming our issuer URL
	if _, err := e.iss.Verify(e.ctx, ot.AccessToken); err == nil {
		t.Error("a foreign key's token was accepted")
	}
	if _, err := e.iss.Verify(e.ctx, "not.a.jwt"); err == nil {
		t.Error("garbage accepted")
	}
}

func (e *env) refresh(rt string) (*oauth2.Token, error) {
	return e.config(oauth2.AuthStyleInParams).TokenSource(e.ctx, &oauth2.Token{RefreshToken: rt, Expiry: time.Unix(1, 0)}).Token()
}

func TestRefreshRotatesAndCatchesReuse(t *testing.T) {
	e := setup(t)
	code, _, _ := e.iss.Invite(e.ctx, "bob", nil, 0)
	t1 := e.login(t, e.config(oauth2.AuthStyleInParams), code)
	t2, err := e.refresh(t1.RefreshToken)
	if err != nil || t2.RefreshToken == t1.RefreshToken {
		t.Fatalf("refresh: %v (rotated: %v)", err, t2 != nil && t2.RefreshToken != t1.RefreshToken)
	}
	if _, err := e.iss.Verify(e.ctx, t2.AccessToken); err != nil {
		t.Fatal(err)
	}
	// Right away, the old one is a race between two commands: refused, session kept.
	if _, err := e.refresh(t1.RefreshToken); err == nil || !strings.Contains(err.Error(), "raced") {
		t.Fatalf("racing refresh: %v", err)
	}
	if _, err := e.iss.Verify(e.ctx, t2.AccessToken); err != nil {
		t.Fatalf("race ended the session: %v", err)
	}
	// Later, the old one coming back means a stolen copy: the whole session ends.
	e.clk.Step(time.Minute)
	if _, err := e.refresh(t1.RefreshToken); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("reused refresh: %v", err)
	}
	if _, err := e.refresh(t2.RefreshToken); err == nil {
		t.Fatal("the session survived a reused refresh token")
	}
	if _, err := e.iss.Verify(e.ctx, t2.AccessToken); err == nil {
		t.Fatal("access token outlived its session")
	}
	// An idle session ends after SessionTTL.
	code, _, _ = e.iss.Invite(e.ctx, "bob", nil, 0)
	t3 := e.login(t, e.config(oauth2.AuthStyleInParams), code)
	e.clk.Step(31 * 24 * time.Hour)
	if _, err := e.refresh(t3.RefreshToken); err == nil {
		t.Fatal("idle session refreshed")
	}
}

func TestDisableEndsEverything(t *testing.T) {
	e := setup(t)
	code, _, _ := e.iss.Invite(e.ctx, "bob", nil, 0)
	tok := e.login(t, e.config(oauth2.AuthStyleInParams), code)
	spare, _, _ := e.iss.Invite(e.ctx, "bob", nil, 0)
	if err := e.iss.Disable(e.ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.iss.Verify(e.ctx, tok.AccessToken); err == nil {
		t.Error("access token works after disable")
	}
	if _, err := e.refresh(tok.RefreshToken); err == nil {
		t.Error("refresh works after disable")
	}
	cfg := e.config(oauth2.AuthStyleInParams)
	// The spare invite was re-enabling him: a new Invite re-enables, an old one doesn't.
	if resp, _ := e.browse(t, cfg.AuthCodeURL("s", oauth2.S256ChallengeOption(oauth2.GenerateVerifier())), spare); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old invite after disable: %d", resp.StatusCode)
	}
	users, _ := e.iss.Users(e.ctx)
	if len(users) != 1 || !users[0].Disabled {
		t.Fatalf("users: %+v", users)
	}
}

func TestDiscoveryAndKeys(t *testing.T) {
	e := setup(t)
	resp, err := http.Get(e.ts.URL + PathDiscovery)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	resp, err = http.Get(e.ts.URL + PathKeys)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	// The signing key survives a restart (it's in the store).
	again, err := New(e.ctx, e.iss.Store, e.clk, e.iss.URL)
	if err != nil || again.kid != e.iss.kid {
		t.Fatalf("key changed across restarts: %v", err)
	}
}

func (e *env) revoke(form url.Values) int {
	resp, err := http.PostForm(e.ts.URL+PathRevoke, form)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestRevokeEndsTheSession(t *testing.T) {
	e := setup(t)
	code, _, _ := e.iss.Invite(e.ctx, "bob", nil, 0)
	t1 := e.login(t, e.config(oauth2.AuthStyleInParams), code)
	code, _, _ = e.iss.Invite(e.ctx, "bob", nil, 0)
	other := e.login(t, e.config(oauth2.AuthStyleInParams), code)

	// Refused outright: an unknown client, no token, GET.
	if c := e.revoke(url.Values{"client_id": {"evil"}, "token": {t1.RefreshToken}}); c != http.StatusUnauthorized {
		t.Fatalf("unknown client: %d", c)
	}
	if c := e.revoke(url.Values{"client_id": {ClientID}}); c != http.StatusBadRequest {
		t.Fatalf("no token: %d", c)
	}
	if resp, err := http.Get(e.ts.URL + PathRevoke); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %v %v", resp, err)
	}
	// A wrong secret for the right session says 200 and ends nothing.
	sid, _, _ := split(t1.RefreshToken, "kvr_")
	if c := e.revoke(url.Values{"client_id": {ClientID}, "token": {"kvr_" + sid + ".nope"}}); c != http.StatusOK {
		t.Fatalf("wrong secret: %d", c)
	}
	if _, err := e.iss.Verify(e.ctx, t1.AccessToken); err != nil {
		t.Fatalf("a wrong secret ended the session: %v", err)
	}
	// The right one ends that session only: its access token stops at once, its refresh fails.
	if c := e.revoke(url.Values{"client_id": {ClientID}, "token": {t1.RefreshToken}, "token_type_hint": {"refresh_token"}}); c != http.StatusOK {
		t.Fatalf("revoke: %d", c)
	}
	if _, err := e.iss.Verify(e.ctx, t1.AccessToken); err == nil {
		t.Fatal("access token outlived a revoked session")
	}
	if _, err := e.refresh(t1.RefreshToken); err == nil {
		t.Fatal("a revoked session refreshed")
	}
	if _, err := e.iss.Verify(e.ctx, other.AccessToken); err != nil {
		t.Fatalf("revoking one session ended another: %v", err)
	}
	// Again, or garbage: still 200 (RFC 7009 §2.2).
	for _, tok := range []string{t1.RefreshToken, "garbage", other.AccessToken} {
		if c := e.revoke(url.Values{"client_id": {ClientID}, "token": {tok}}); c != http.StatusOK {
			t.Fatalf("revoke %q: %d", tok[:5], c)
		}
	}
	if _, err := e.iss.Verify(e.ctx, other.AccessToken); err != nil {
		t.Fatalf("revoking an access token ended its session: %v", err)
	}
	// The just-replaced refresh token also ends the session (its holder had the session).
	t2, err := e.refresh(other.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if c := e.revoke(url.Values{"client_id": {ClientID}, "token": {other.RefreshToken}}); c != http.StatusOK {
		t.Fatalf("revoke previous: %d", c)
	}
	if _, err := e.iss.Verify(e.ctx, t2.AccessToken); err == nil {
		t.Fatal("the previous refresh token didn't end its session")
	}
}
