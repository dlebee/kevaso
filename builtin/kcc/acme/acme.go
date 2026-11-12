// Package acme is the built-in "acme" cert-controller, cert-manager style: certificates from any
// ACME server (Let's Encrypt, or a private one), proving control of each host with a solver the
// Issuer picks per host:
//
//   - http01: answered by the cluster's ingress controllers on port 80 (the default);
//   - dns01: a TXT record at _acme-challenge.<host>, written by a DNS provider registered on the
//     control-plane host (needed for wildcards, and for hosts nothing can reach on port 80).
//
// Its ACME account key is kept in a Store the control plane seals.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"

	"kevaso.com/core/sdk/kcc"
)

// Config is an Issuer's acme settings.
type Config struct {
	Server   string `json:"server"` // directory URL
	Email    string `json:"email,omitempty"`
	ServerCA string `json:"serverCA,omitempty"` // PEM, for a private ACME server
	// Solvers say how each host is proven, cert-manager style: the most specific selector wins
	// (dnsNames, then the longest dnsZones match, then a solver without a selector). Default: one
	// http01 solver for every host.
	Solvers []SolverConfig `json:"solvers,omitempty"`
}

// SolverConfig is one way of answering challenges, for the hosts its selector matches.
type SolverConfig struct {
	Selector *Selector `json:"selector,omitempty"`
	HTTP01   *HTTP01   `json:"http01,omitempty"`
	DNS01    *DNS01    `json:"dns01,omitempty"`
}

// Selector picks hosts: exact names, or every name in (or under) a zone.
type Selector struct {
	DNSNames []string `json:"dnsNames,omitempty"`
	DNSZones []string `json:"dnsZones,omitempty"`
}

// HTTP01 answers on port 80 through the cluster's ingress controllers.
type HTTP01 struct{}

// DNS01 answers with a TXT record written by a DNS provider.
type DNS01 struct {
	// Provider is a DNS provider registered on the control-plane host (kevasod control-plane
	// --dns-provider NAME=COMMAND). Issuers name providers; they can't bring commands.
	Provider string `json:"provider"`
	// PropagationSeconds is how long to wait after writing the record before the ACME server
	// checks it (default 60).
	PropagationSeconds int `json:"propagationSeconds,omitempty"`
}

// Challenge types.
const (
	HTTP01Type = "http-01"
	DNS01Type  = "dns-01"
)

// HTTP01Solver serves HTTP-01 answers (the control plane's, through the ingress controllers).
type HTTP01Solver interface {
	Present(ctx context.Context, host, token, keyAuth string) error
	CleanUp(ctx context.Context, token string) error
}

// DNSProvider writes and removes TXT records. fqdn ends with a dot
// (_acme-challenge.example.com.); value is the record's text.
type DNSProvider interface {
	Present(ctx context.Context, fqdn, value string) error
	CleanUp(ctx context.Context, fqdn, value string) error
}

// Store keeps the controller's state per issuer (its account key), sealed by the control plane.
type Store interface {
	Get(ctx context.Context, issuer, key string) ([]byte, error) // ErrNotFound if missing
	Put(ctx context.Context, issuer, key string, value []byte) error
}

// ErrNotFound: no such key in the Store.
var ErrNotFound = errors.New("acme: not found")

// Controller is the acme cert-controller.
type Controller struct {
	HTTP01 HTTP01Solver
	// DNSProviders are the DNS providers dns01 solvers may name.
	DNSProviders map[string]DNSProvider
	// DNSLookup, if set, finds DNS providers not in DNSProviders (plugins that come and go).
	DNSLookup func(name string) DNSProvider
	Store     Store
	// HTTP, if set, is the client for ACME servers (tests).
	HTTP *http.Client
	// Pickup is how long to give the solver's answer to reach the ingress controllers before the
	// server checks (they refresh every few seconds).
	Pickup time.Duration
}

// Info implements kcc.CertController.
func (c *Controller) Info() kcc.Info {
	return kcc.Info{Name: "acme", Description: "an ACME server (Let's Encrypt or your own), with http01 and dns01 solvers"}
}

const accountKey = "account-key"

func (c *Controller) client(ctx context.Context, issuer string, cfg Config) (*xacme.Client, error) {
	hc := c.HTTP
	if hc == nil && cfg.ServerCA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.ServerCA)) {
			return nil, errors.New("acme: serverCA has no certificate")
		}
		hc = &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	}
	var key crypto.Signer
	fresh := false
	switch der, err := c.Store.Get(ctx, issuer, accountKey); {
	case errors.Is(err, ErrNotFound):
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		if err := c.Store.Put(ctx, issuer, accountKey, b); err != nil {
			return nil, err
		}
		key, fresh = k, true
	case err != nil:
		return nil, err
	default:
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		key = k.(crypto.Signer)
	}
	cl := &xacme.Client{Key: key, DirectoryURL: cfg.Server, HTTPClient: hc, UserAgent: "kevaso"}
	if fresh {
		acct := &xacme.Account{}
		if cfg.Email != "" {
			acct.Contact = []string{"mailto:" + cfg.Email}
		}
		if _, err := cl.Register(ctx, acct, xacme.AcceptTOS); err != nil && !errors.Is(err, xacme.ErrAccountAlreadyExists) {
			return nil, fmt.Errorf("acme account: %w", err)
		}
	}
	return cl, nil
}

// Issue implements kcc.CertController: an order, a challenge per host answered by a solver, then
// the CSR.
func (c *Controller) Issue(ctx context.Context, r kcc.Request) ([][]byte, error) {
	var cfg Config
	if err := json.Unmarshal(r.Config, &cfg); err != nil || cfg.Server == "" {
		return nil, fmt.Errorf("acme: the issuer needs a server (directory URL): %v", err)
	}
	if len(cfg.Solvers) == 0 {
		cfg.Solvers = []SolverConfig{{HTTP01: &HTTP01{}}}
	}
	for _, sc := range cfg.Solvers {
		if err := c.checkSolver(sc); err != nil {
			return nil, err
		}
	}
	hosts, csr := r.Hosts, r.CSR
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cl, err := c.client(ctx, r.Issuer, cfg)
	if err != nil {
		return nil, err
	}
	order, err := cl.AuthorizeOrder(ctx, xacme.DomainIDs(hosts...))
	if err != nil {
		return nil, fmt.Errorf("acme order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return nil, err
		}
		if z.Status == xacme.StatusValid {
			continue
		}
		host := z.Identifier.Value
		if z.Wildcard {
			host = "*." + host
		}
		sc, ok := Pick(cfg.Solvers, host)
		if !ok {
			return nil, fmt.Errorf("%s: no solver of the issuer matches this host", host)
		}
		cleanup, wait, ch, err := c.present(ctx, cl, z, sc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", host, err)
		}
		defer cleanup()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		if _, err := cl.Accept(ctx, ch); err != nil {
			return nil, fmt.Errorf("%s: accept: %w", host, err)
		}
		if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
			hint := "does it point at the ingress controller, on port 80?"
			if sc.DNS01 != nil {
				hint = "is the TXT record visible to the ACME server? (propagationSeconds)"
			}
			return nil, fmt.Errorf("%s: %w (%s)", host, err, hint)
		}
	}
	ready, err := cl.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("acme order: %w", err)
	}
	if ready.FinalizeURL == "" {
		ready.FinalizeURL = order.FinalizeURL
	}
	// With the order (not just its finalize URL): a CA that answers "processing" without a
	// Location header is then polled at the order's own URL.
	der, _, err := cl.CreateCertFromOrder(ctx, ready, csr, true)
	if err != nil {
		return nil, fmt.Errorf("acme finalize: %w", err)
	}
	return der, nil
}

func (c *Controller) dnsProvider(name string) DNSProvider {
	if p := c.DNSProviders[name]; p != nil {
		return p
	}
	if c.DNSLookup != nil {
		return c.DNSLookup(name)
	}
	return nil
}

func (c *Controller) checkSolver(sc SolverConfig) error {
	switch {
	case (sc.HTTP01 != nil) == (sc.DNS01 != nil):
		return errors.New("acme: each solver is exactly one of http01 or dns01")
	case sc.HTTP01 != nil && c.HTTP01 == nil:
		return errors.New("acme: http01 isn't served here")
	case sc.DNS01 != nil && c.dnsProvider(sc.DNS01.Provider) == nil:
		return fmt.Errorf("acme: no DNS provider %q on the control plane (a plugin serving it, or kevasod control-plane --dns-provider %s=COMMAND)", sc.DNS01.Provider, sc.DNS01.Provider)
	}
	return nil
}

// present answers z's challenge with sc, returning how to clean up and how long to wait before
// asking the server to check.
func (c *Controller) present(ctx context.Context, cl *xacme.Client, z *xacme.Authorization, sc SolverConfig) (func(), time.Duration, *xacme.Challenge, error) {
	typ := HTTP01Type
	if sc.DNS01 != nil {
		typ = DNS01Type
	}
	var ch *xacme.Challenge
	for _, x := range z.Challenges {
		if x.Type == typ {
			ch = x
		}
	}
	if ch == nil {
		return nil, 0, nil, fmt.Errorf("the ACME server offers no %s challenge", typ)
	}
	bg := context.WithoutCancel(ctx)
	if sc.DNS01 != nil {
		value, err := cl.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return nil, 0, nil, err
		}
		fqdn := "_acme-challenge." + z.Identifier.Value + "."
		p := c.dnsProvider(sc.DNS01.Provider)
		if err := p.Present(ctx, fqdn, value); err != nil {
			return nil, 0, nil, fmt.Errorf("dns provider %s: %w", sc.DNS01.Provider, err)
		}
		wait := time.Duration(sc.DNS01.PropagationSeconds) * time.Second
		if wait <= 0 {
			wait = time.Minute
		}
		return func() { _ = p.CleanUp(bg, fqdn, value) }, wait, ch, nil
	}
	if z.Wildcard {
		return nil, 0, nil, errors.New("wildcards need a dns01 solver")
	}
	keyAuth, err := cl.HTTP01ChallengeResponse(ch.Token)
	if err != nil {
		return nil, 0, nil, err
	}
	if err := c.HTTP01.Present(ctx, z.Identifier.Value, ch.Token, keyAuth); err != nil {
		return nil, 0, nil, err
	}
	wait := c.Pickup
	if wait <= 0 {
		wait = 6 * time.Second
	}
	return func() { _ = c.HTTP01.CleanUp(bg, ch.Token) }, wait, ch, nil
}

// Pick is the solver for host: one whose dnsNames list it, else the one with the longest dnsZones
// match, else the first without a selector.
func Pick(solvers []SolverConfig, host string) (SolverConfig, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	best, bestLen, found := SolverConfig{}, -1, false
	for _, sc := range solvers {
		if sc.Selector == nil {
			if bestLen < 0 {
				best, bestLen, found = sc, 0, true
			}
			continue
		}
		for _, n := range sc.Selector.DNSNames {
			if strings.EqualFold(strings.TrimSuffix(n, "."), host) {
				return sc, true
			}
		}
		for _, z := range sc.Selector.DNSZones {
			z = strings.ToLower(strings.TrimSuffix(z, "."))
			bare := strings.TrimPrefix(host, "*.")
			if (bare == z || strings.HasSuffix(bare, "."+z)) && len(z) > bestLen {
				best, bestLen, found = sc, len(z), true
			}
		}
	}
	return best, found
}

var _ kcc.CertController = (*Controller)(nil)
