// Package kvoconfig is kvo's config file (~/.kevaso/config.yaml, or $KVO_CONFIG), kubeconfig-style:
// named contexts, each a server, the cluster CA to pin, a default namespace, and credentials: a
// client certificate and key (under ~/.kevaso/contexts/<name>/, key 0600; kvoadm keeps its own,
// per cluster, in ~/.kevaso/clusters/<name>/: package admconfig)
// or a `kvo login` session, whose tokens live in the token store, never in this file.
package kvoconfig

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/login"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/tokenstore"
)

// warnCert is where a certificate that could not be renewed, and expires within ten days, is
// reported. Tests replace it.
var warnCert = func(format string, args ...any) { fmt.Fprintf(os.Stderr, format, args...) }

// Context is one cluster to talk to.
type Context struct {
	Server      string `yaml:"server"`
	CA          string `yaml:"ca"`
	Certificate string `yaml:"certificate,omitempty"`
	Key         string `yaml:"key,omitempty"`
	Login       bool   `yaml:"login,omitempty"`     // signed in with kvo login: tokens in the token store
	Namespace   string `yaml:"namespace,omitempty"` // default for -n (kvo ns)
}

// Config is the whole file.
type Config struct {
	CurrentContext string             `yaml:"current-context"`
	Contexts       map[string]Context `yaml:"contexts"`
}

// Path is $KVO_CONFIG, or ~/.kevaso/config.yaml.
func Path() (string, error) {
	if p := os.Getenv("KVO_CONFIG"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".kevaso", "config.yaml"), nil
}

// Load reads the config; a missing file is an empty config.
func Load(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{Contexts: map[string]Context{}}, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if c.Contexts == nil {
		c.Contexts = map[string]Context{}
	}
	return c, nil
}

// Save writes the config (0600).
func (c Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// AddContext stores credentials as files next to the config, adds the context and makes it current.
func AddContext(path, name, server string, caPEM, certPEM, keyPEM []byte) error {
	c, err := Load(path)
	if err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(path), "contexts", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ctx := Context{
		Server:      server,
		CA:          filepath.Join(dir, "ca.crt"),
		Certificate: filepath.Join(dir, "client.crt"),
		Key:         filepath.Join(dir, "client.key"),
	}
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{{ctx.CA, caPEM, 0o644}, {ctx.Certificate, certPEM, 0o644}, {ctx.Key, keyPEM, 0o600}} {
		if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
			return err
		}
	}
	c.Contexts[name] = ctx
	c.CurrentContext = name
	return c.Save(path)
}

// AddLoginContext saves a context for a kvo login session (the CA as a file; the tokens go to the
// token store separately) and makes it current.
func AddLoginContext(path, name, server string, caPEM []byte) error {
	c, err := Load(path)
	if err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(path), "contexts", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ctx := Context{Server: server, CA: filepath.Join(dir, "ca.crt"), Login: true, Namespace: c.Contexts[name].Namespace}
	if err := os.WriteFile(ctx.CA, caPEM, 0o644); err != nil {
		return err
	}
	c.Contexts[name] = ctx
	c.CurrentContext = name
	return c.Save(path)
}

// Tokens is where kvo login sessions are kept for the config at path.
func Tokens(path string) tokenstore.Store {
	return tokenstore.Default(filepath.Join(filepath.Dir(path), "tokens"))
}

// Resolve names the context ("" = the current one) and returns it.
func (c Config) Resolve(name string) (string, Context, error) {
	if name == "" {
		name = c.CurrentContext
	}
	ctx, ok := c.Contexts[name]
	if !ok {
		return name, ctx, fmt.Errorf("no context %q in the kvo config (kvo login or kvoadm init writes one)", name)
	}
	return name, ctx, nil
}

// Client builds an API client for a context ("" = the current one). path is the config file's,
// for where the context's tokens and locks are.
func (c Config) Client(path, name string) (*client.Client, string, error) {
	name, ctx, err := c.Resolve(name)
	if err != nil {
		return nil, name, err
	}
	read := os.ReadFile
	ca, err := read(ctx.CA)
	if err != nil {
		return nil, "", err
	}
	if ctx.Login {
		// A server may list several control planes, comma-separated: the client fails over between
		// them. Logins refresh at the first (an HA cluster gives its control plane one DNS name).
		servers := client.SplitServers(ctx.Server)
		if len(servers) == 0 {
			return nil, name, fmt.Errorf("context %s has no server", name)
		}
		cl, err := client.NewTLSEndpoints(servers, ca, nil, nil)
		if err != nil {
			return nil, name, err
		}
		cl.Token = login.Tokens(servers[0], ca, Tokens(path), name, filepath.Join(filepath.Dir(path), "locks"))
		return cl, name, nil
	}
	cl, err := CertClient(name, ctx, ca)
	return cl, name, err
}

// CertClient builds an API client from a certificate context, with the cluster CA given (kvoadm
// keeps it in its cluster file, not as a file of its own). The certificate is renewed in place
// when it's due, as for kvo.
func CertClient(name string, ctx Context, ca []byte) (*client.Client, error) {
	cert, err := os.ReadFile(ctx.Certificate)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(ctx.Key)
	if err != nil {
		return nil, err
	}
	cert, key, err = renewContextCert(name, ctx, ca, cert, key)
	if err != nil {
		return nil, err
	}
	return client.NewTLSEndpoints(client.SplitServers(ctx.Server), ca, cert, key)
}

// renewContextCert renews a certificate user's client certificate once it is past two thirds of
// its life, or inside the last ten days. An expired certificate is an error naming how to sign a
// new one. A renewal that fails inside the last ten days is warned about, and the current
// certificate is still used: it can still connect. A renewed certificate for a different identity
// is refused and not stored.
func renewContextCert(name string, ctx Context, ca, cert, key []byte) ([]byte, []byte, error) {
	nb, na, ok := pki.CertificateLifetime(cert)
	if !ok {
		return cert, key, nil // not a certificate (a test's stand-in, or a file the TLS client will reject)
	}
	now := time.Now()
	id, idErr := pki.IdentityOfPEM(cert)
	who := id.Name
	if who == "" {
		who = name
	}
	if !now.Before(na) {
		return nil, nil, fmt.Errorf("context %s certificate for %s expired on %s. Run: %s",
			name, who, na.UTC().Format(time.RFC3339), CertRecovery(who, ctx.Server))
	}
	if client.RenewDue(nb, na, now) { // renew a certificate past two thirds of its life
		cl, err := client.NewTLSEndpoints(client.SplitServers(ctx.Server), ca, cert, key)
		if err != nil {
			return cert, key, nil
		}
		rctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cred, rerr := cl.Renew(rctx)
		cancel()
		within10 := !now.Before(na.Add(-10 * 24 * time.Hour))
		if rerr != nil {
			if within10 {
				warnCert("kvo: context %s certificate for %s expires on %s and could not be renewed (%v). Run: %s\n",
					name, who, na.UTC().Format(time.RFC3339), rerr, CertRecovery(who, ctx.Server))
			}
			return cert, key, nil
		}
		if idErr == nil {
			newID, err := pki.IdentityOfPEM(cred.Certificate)
			if err != nil {
				return nil, nil, err
			}
			if newID != id { // a renewal is the same identity
				return nil, nil, fmt.Errorf("context %s: refusing a renewed certificate for %s %s (this context is %s %s)",
					name, newID.Type, newID.Name, id.Type, id.Name)
			}
		}
		if err := writeFileAtomic(ctx.Key, cred.Key, 0o600); err != nil {
			return nil, nil, err
		}
		if err := writeFileAtomic(ctx.Certificate, cred.Certificate, 0o644); err != nil {
			return nil, nil, err
		}
		return cred.Certificate, cred.Key, nil
	}
	return cert, key, nil
}

// CertRecovery is the command that signs a new client certificate over SSH, the way
// kvoadm init does: the key stays here, and only the request goes to the control plane.
func CertRecovery(user, server string) string {
	return "kvoadm users resign root@" + serverHost(server) + " --name " + user
}

func serverHost(server string) string {
	first := server
	if i := strings.Index(server, ","); i >= 0 {
		first = strings.TrimSpace(server[:i])
	}
	u, err := url.Parse(first)
	if err != nil || u.Hostname() == "" {
		first = strings.TrimPrefix(strings.TrimPrefix(first, "https://"), "http://")
		if h, _, ok := strings.Cut(first, ":"); ok {
			return h
		}
		if first == "" {
			return "CONTROL-PLANE"
		}
		return first
	}
	return u.Hostname()
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
