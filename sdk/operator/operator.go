// Package operator is what a plugin's controller needs from how `kvoadm plugin install` runs it
// (ADR 0006): its credentials, and a heartbeat on its Plugin.
//
// The controller runs as a systemd unit, as the plugin's own service account. Its credentials come
// through systemd (LoadCredential, readable by the unit alone, never on a command line or in the
// environment): in $CREDENTIALS_DIRECTORY, server (the API's URL), ca.pem (the cluster's CA),
// plugin.json (its name, version and service account) and token.json (a token good for an hour).
// The controller renews its token itself, well before it expires, and keeps the renewed one in
// $STATE_DIRECTORY/token.json (systemd's StateDirectory: the unit's own, kept across restarts).
//
//	creds, err := operator.FromEnv()
//	c, err := creds.Client(ctx)
//	go operator.Heartbeat(ctx, c, creds.Plugin.Name, creds.Plugin.Version)
package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

// TokenLifetime is how long each token works; a controller renews at half of that.
const TokenLifetime = time.Hour

// Identity is plugin.json: who the controller is.
type Identity struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	ServiceAccount string `json:"serviceAccount"` // NAMESPACE/NAME
}

// Token is token.json.
type Token struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

// Credentials are a controller's credentials, read from Dir; renewed tokens go to StateDir.
type Credentials struct {
	Dir, StateDir string
	Server        string
	CA            []byte
	Plugin        Identity

	// Now is the clock (default time.Now); tests set it.
	Now func() time.Time
}

// FromEnv reads the credentials systemd gives the unit.
func FromEnv() (*Credentials, error) {
	dir, state := os.Getenv("CREDENTIALS_DIRECTORY"), os.Getenv("STATE_DIRECTORY")
	if dir == "" || state == "" {
		return nil, errors.New("no $CREDENTIALS_DIRECTORY or $STATE_DIRECTORY: run as kvoadm plugin install sets it up")
	}
	return Load(dir, state)
}

// Load reads the credentials in dir (and a renewed token in state, if there is one).
func Load(dir, state string) (*Credentials, error) {
	c := &Credentials{Dir: dir, StateDir: state}
	server, err := os.ReadFile(filepath.Join(dir, "server"))
	if err != nil {
		return nil, err
	}
	c.Server = strings.TrimSpace(string(server))
	if c.CA, err = os.ReadFile(filepath.Join(dir, "ca.pem")); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "plugin.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &c.Plugin); err != nil {
		return nil, fmt.Errorf("plugin.json: %w", err)
	}
	if ns, name, ok := strings.Cut(c.Plugin.ServiceAccount, "/"); !ok || ns == "" || name == "" {
		return nil, fmt.Errorf("plugin.json: serviceAccount %q: want NAMESPACE/NAME", c.Plugin.ServiceAccount)
	}
	return c, nil
}

func (c *Credentials) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Client is an API client that authenticates as the controller's service account, renewing its
// token as it goes.
func (c *Credentials) Client(ctx context.Context) (*client.Client, error) {
	cl, err := client.NewTLS(c.Server, c.CA, nil, nil)
	if err != nil {
		return nil, err
	}
	ts := &tokens{creds: c, http: cl.HTTP, base: cl.BaseURL}
	if _, err := ts.Token(ctx); err != nil {
		return nil, err
	}
	cl.Token = ts.Token
	return cl, nil
}

// tokens hands out the current token and renews it at half its life.
type tokens struct {
	creds *Credentials
	http  *http.Client
	base  string

	mu  sync.Mutex
	cur Token
}

func readToken(path string) (Token, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Token{}, false
	}
	var t Token
	if json.Unmarshal(b, &t) != nil || t.Token == "" {
		return Token{}, false
	}
	return t, true
}

// Token returns a token that works now.
func (t *tokens) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.creds.now()
	if t.cur.Token == "" { // the later of the installed token and a renewed one
		for _, p := range []string{filepath.Join(t.creds.Dir, "token.json"), filepath.Join(t.creds.StateDir, "token.json")} {
			if tok, ok := readToken(p); ok && tok.Expires.After(t.cur.Expires) {
				t.cur = tok
			}
		}
	}
	if !t.cur.Expires.After(now) {
		return "", fmt.Errorf("plugin %s: its token expired at %s: run kvoadm plugin install again to give it a new one",
			t.creds.Plugin.Name, t.cur.Expires.Format(time.RFC3339))
	}
	if t.cur.Expires.Sub(now) > TokenLifetime/2 {
		return t.cur.Token, nil
	}
	next, err := t.renew(ctx)
	if err != nil {
		return t.cur.Token, nil // still good for a while: try again on the next call
	}
	t.cur = next
	if b, err := json.Marshal(next); err == nil {
		_ = os.WriteFile(filepath.Join(t.creds.StateDir, "token.json"), b, 0o600)
	}
	return next.Token, nil
}

// renew asks for a new token for the controller's own service account, with the current one.
func (t *tokens) renew(ctx context.Context) (Token, error) {
	ns, name, _ := strings.Cut(t.creds.Plugin.ServiceAccount, "/")
	c := &client.Client{BaseURL: t.base, HTTP: t.http}
	cur := t.cur.Token
	c.Token = func(context.Context) (string, error) { return cur, nil }
	p, err := client.Path("ServiceAccount", ns, name)
	if err != nil {
		return Token{}, err
	}
	var resp client.TokenResponse
	if err := c.Call(ctx, http.MethodPost, p+"/token", client.TokenRequest{Duration: TokenLifetime.String()}, &resp); err != nil {
		return Token{}, err
	}
	return Token{Token: resp.Token, Expires: resp.Expires}, nil
}

// Heartbeat reports the controller alive on its Plugin's status every v1.HeartbeatEvery until ctx
// ends, so `kvoadm plugin list` can tell whether it runs.
func Heartbeat(ctx context.Context, c *client.Client, plugin, version string) {
	for {
		_ = Beat(ctx, c, plugin, version, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(v1.HeartbeatEvery):
		}
	}
}

// Beat writes one heartbeat.
func Beat(ctx context.Context, c *client.Client, plugin, version string, now time.Time) error {
	for attempt := 0; attempt < 3; attempt++ {
		var p v1.Plugin
		if err := c.Get(ctx, "Plugin", "", plugin, &p); err != nil {
			return err
		}
		t := now.UTC().Truncate(time.Second)
		p.Status.Controller = v1.PluginControllerStatus{Heartbeat: &t, Version: version}
		err := c.UpdateStatus(ctx, &p)
		if !client.IsConflict(err) {
			return err
		}
	}
	return errors.New("heartbeat: the plugin keeps changing")
}
