// Package kvoconfig is kvo's config file (~/.kevaso/config.yaml, or $KVO_CONFIG), kubeconfig-style:
// named contexts, each a server, the cluster CA to pin, and a client certificate and key, kept as
// files under ~/.kevaso/clusters/<name>/ (key 0600).
package kvoconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	yaml "go.yaml.in/yaml/v3"

	"kevaso.com/core/api/client"
)

// Context is one cluster to talk to.
type Context struct {
	Server      string `yaml:"server"`
	CA          string `yaml:"ca"`
	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`
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
	dir := filepath.Join(filepath.Dir(path), "clusters", name)
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

// Client builds an API client for a context ("" = the current one).
func (c Config) Client(name string) (*client.Client, string, error) {
	if name == "" {
		name = c.CurrentContext
	}
	ctx, ok := c.Contexts[name]
	if !ok {
		return nil, "", fmt.Errorf("no context %q in the kvo config (kvoadm init writes one)", name)
	}
	read := os.ReadFile
	ca, err := read(ctx.CA)
	if err != nil {
		return nil, "", err
	}
	cert, err := read(ctx.Certificate)
	if err != nil {
		return nil, "", err
	}
	key, err := read(ctx.Key)
	if err != nil {
		return nil, "", err
	}
	cl, err := client.NewTLS(ctx.Server, ca, cert, key)
	return cl, name, err
}
