// Package login is the client side of `kvo login` (design §9.2, §9.4, research E022): pin the
// cluster CA by its fingerprint, sign in through the browser with authorization code + PKCE on a
// loopback redirect, and keep the tokens fresh.
//
// The browser never talks to the control plane directly: kvo serves http://127.0.0.1:PORT, relays
// the sign-in pages to the control plane over TLS checked against the pinned CA, and receives the
// redirect on the same port. So a private CA causes no certificate warning, and nothing is
// unverified.
package login

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/issuer"
)

// FetchCA downloads the cluster CA and accepts it only if it has the fingerprint the admin gave.
func FetchCA(ctx context.Context, server, fingerprint string) ([]byte, error) {
	// The certificate isn't trusted yet, so this one request skips verification; what it returns
	// is then checked against the fingerprint, and every later request verifies against it.
	hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, //nolint:gosec // checked by fingerprint below
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(server, "/")+"/ca.crt", nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	pemBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	got, err := client.Fingerprint(pemBytes)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(got, fingerprint) {
		return nil, fmt.Errorf("the cluster's CA is %s, not the %s you were given: not trusting it", got, fingerprint)
	}
	// And the server really holds a certificate from that CA.
	pinned, err := HTTPClient(pemBytes)
	if err != nil {
		return nil, err
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(server, "/")+"/healthz", nil)
	resp, err = pinned.Do(req)
	if err != nil {
		return nil, fmt.Errorf("server's certificate isn't from that CA: %w", err)
	}
	_ = resp.Body.Close()
	return pemBytes, nil
}

// HTTPClient talks TLS 1.3 to a server whose certificate comes from caPEM.
func HTTPClient(caPEM []byte) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA: no certificate in PEM")
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true,
	}}, nil
}

// Config is the OAuth2 client for a server, with the redirect on the given loopback base.
func Config(server, loopbackBase string) *oauth2.Config {
	server = strings.TrimRight(server, "/")
	return &oauth2.Config{
		ClientID: issuer.ClientID, Scopes: []string{"openid", "offline_access", "groups"},
		RedirectURL: loopbackBase + "/callback",
		Endpoint: oauth2.Endpoint{AuthURL: loopbackBase + issuer.PathAuthorize, TokenURL: server + issuer.PathToken,
			AuthStyle: oauth2.AuthStyleInParams}, // a public client (E022)
	}
}

// Options for Login.
type Options struct {
	// Open shows the sign-in page (the system browser by default). Tests play the browser here.
	Open func(url string) error
	// Say tells the person what's happening.
	Say func(format string, args ...any)
	// Timeout for the whole sign-in; default 5 minutes.
	Timeout time.Duration
}

// Login signs in through the browser and returns the tokens.
func Login(ctx context.Context, server string, caPEM []byte, o Options) (*oauth2.Token, error) {
	if o.Say == nil {
		o.Say = func(string, ...any) {}
	}
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	pinned, err := HTTPClient(caPEM)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	base := "http://" + l.Addr().String()
	cfg := Config(server, base)
	state, nonce, verifier := random(16), random(16), oauth2.GenerateVerifier()

	type result struct {
		code string
		err  error
	}
	got := make(chan result, 1)
	proxy := &httputil.ReverseProxy{
		Rewrite:   func(r *httputil.ProxyRequest) { r.SetURL(target); r.Out.Host = target.Host },
		Transport: pinned.Transport,
	}
	mux := http.NewServeMux()
	mux.Handle(issuer.PathAuthorize, proxy) // only the sign-in pages are relayed
	mux.Handle(issuer.PathLogin, proxy)
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var res result
		switch {
		case q.Get("state") != state:
			res.err = errors.New("state mismatch: callback refused")
		case q.Get("error") != "":
			res.err = fmt.Errorf("sign-in failed: %s %s", q.Get("error"), q.Get("error_description"))
		case q.Get("code") == "":
			res.err = errors.New("no code in the callback")
		default:
			res.code = q.Get("code")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if res.err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "<!doctype html><title>Kevaso</title><p>Sign-in failed. Check your terminal.</p>")
		} else {
			_, _ = fmt.Fprintf(w, "<!doctype html><title>Kevaso</title><p>Signed in. You can close this tab and go back to your terminal.</p>")
		}
		select {
		case got <- res:
		default:
		}
	})
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = hs.Serve(l) }()
	defer func() { _ = hs.Close() }()

	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce))
	open := o.Open
	if open == nil {
		open = OpenBrowser
	}
	o.Say("Opening your browser to sign in. If it doesn't open, visit:\n  %s", authURL)
	if err := open(authURL); err != nil {
		o.Say("(couldn't open a browser: %v)", err)
	}
	var res result
	select {
	case res = <-got:
	case <-ctx.Done():
		return nil, errors.New("sign-in timed out")
	}
	if res.err != nil {
		return nil, res.err
	}
	return cfg.Exchange(context.WithValue(ctx, oauth2.HTTPClient, pinned), res.code, oauth2.VerifierOption(verifier))
}

func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
