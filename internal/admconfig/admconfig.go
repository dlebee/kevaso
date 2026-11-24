// Package admconfig is kvoadm's own configuration: one folder per cluster,
// ~/.kevaso/clusters/CLUSTER/ (or $KVOADM_HOME/clusters/CLUSTER/), holding two files.
//
// cluster.yaml is the team's, meant to be committed to a shared repository. It holds nothing
// secret, and kvoadm refuses one that does:
//
//	cluster: home
//	server: https://cp1:6443,https://cp2:6443
//	ca: |
//	  -----BEGIN CERTIFICATE-----
//	  …
//	hosts:
//	  sys:   {addresses: [root@203.0.113.9]}
//	  home1: {addresses: [root@192.168.1.50, root@home1.tailnet.ts.net]}
//	admins:
//	  - name: david
//	    sshKeys: ["ssh-ed25519 AAAA… david@laptop"]
//
// local.yaml is this machine's alone, never committed (the folder's .gitignore keeps everything
// but cluster.yaml out): which admin you are, your SSH private key's path, your admin credential
// (admin.crt and admin.key beside it), the host keys you pinned, and addresses only you use, tried
// before the shared ones:
//
//	admin: david
//	sshKey: /Users/david/.ssh/id_ed25519
//	certificate: admin.crt
//	key: admin.key
//	hosts:
//	  home1: {addresses: [root@10.0.0.7], hostKey: SHA256:…}
//
// The admins' public keys are what `kvoadm admins sync` puts on every host's authorized_keys, so
// adding an admin is a commit and a sync. kvo's file (~/.kevaso/config.yaml) is separate, a
// kubeconfig of its own: kvoadm never takes its cluster from kvo's current context.
package admconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/kvoconfig"
)

// EnvCluster names the cluster when --cluster isn't given.
const EnvCluster = "KVOADM_CLUSTER"

// EnvHome replaces ~/.kevaso as the folder that holds clusters/.
const EnvHome = "KVOADM_HOME"

// SharedFile and LocalFile are the two files in a cluster's folder.
const (
	SharedFile = "cluster.yaml"
	LocalFile  = "local.yaml"
)

// gitignore keeps everything but the shared file out of a repository made of the folder.
const gitignore = "# kvoadm: only cluster.yaml is shared. local.yaml, credentials and keys stay on this machine.\n*\n!cluster.yaml\n!.gitignore\n"

// Shared is cluster.yaml: what a team of admins keeps together. Nothing in it is secret.
type Shared struct {
	Cluster string                `yaml:"cluster"`
	Server  string                `yaml:"server"`           // control planes, comma-separated
	CA      string                `yaml:"ca"`               // the cluster CA certificate (PEM)
	Hosts   map[string]SharedHost `yaml:"hosts,omitempty"`  // by the Host's name
	Admins  []Admin               `yaml:"admins,omitempty"` // whose keys every host lets in
}

// SharedHost is how the team reaches a host: addresses in the order to try,
// [USER@]ADDRESS[:PORT], an IP or a hostname.
type SharedHost struct {
	Addresses []string `yaml:"addresses,omitempty"`
}

// Admin is one administrator and the SSH public keys they log in with.
type Admin struct {
	Name    string   `yaml:"name"`
	SSHKeys []string `yaml:"sshKeys,omitempty"` // authorized_keys lines
}

// Local is local.yaml: this machine's part.
type Local struct {
	Admin       string               `yaml:"admin,omitempty"`  // which of the admins this is
	SSHKey      string               `yaml:"sshKey,omitempty"` // this admin's private key (a path)
	Certificate string               `yaml:"certificate,omitempty"`
	Key         string               `yaml:"key,omitempty"`
	Hosts       map[string]LocalHost `yaml:"hosts,omitempty"`
}

// LocalHost is this machine's addition for one host.
type LocalHost struct {
	Addresses []string `yaml:"addresses,omitempty"` // tried before the shared ones
	HostKey   string   `yaml:"hostKey,omitempty"`   // the SSH host key pinned for it (SHA256:…)
}

// Config is one cluster: both files and the folder.
type Config struct {
	Shared Shared
	Local  Local
	dir    string
}

// Root is the folder that holds clusters/: $KVOADM_HOME, else ~/.kevaso.
func Root() (string, error) {
	if p := os.Getenv(EnvHome); p != "" {
		return p, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".kevaso"), nil
}

// Dir is a cluster's folder under root.
func Dir(root, cluster string) string { return filepath.Join(root, "clusters", cluster) }

// Clusters lists the clusters under root that have a cluster.yaml, sorted.
func Clusters(root string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(root, "clusters"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && fileExists(filepath.Join(root, "clusters", e.Name(), SharedFile)) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// Pick names the cluster to act on: the flag, else $KVOADM_CLUSTER, else the only one there is.
func Pick(root, flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if v := os.Getenv(EnvCluster); v != "" {
		return v, nil
	}
	cs, err := Clusters(root)
	if err != nil {
		return "", err
	}
	switch len(cs) {
	case 0:
		return "", fmt.Errorf("no cluster in %s (kvoadm init makes one)", filepath.Join(root, "clusters"))
	case 1:
		return cs[0], nil
	}
	return "", fmt.Errorf("%d clusters in %s (%s): pick one with --cluster NAME or %s",
		len(cs), filepath.Join(root, "clusters"), strings.Join(cs, ", "), EnvCluster)
}

// New is an empty config for a cluster's folder under root (not written yet).
func New(root, cluster string) *Config {
	return &Config{Shared: Shared{Cluster: cluster}, dir: Dir(root, cluster)}
}

// Load reads a cluster's two files. A missing local.yaml is an empty one (a teammate's clone).
func Load(root, cluster string) (*Config, error) {
	c := &Config{dir: Dir(root, cluster)}
	b, err := os.ReadFile(c.SharedPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no cluster %q: %s doesn't exist (kvoadm init makes it)", cluster, c.SharedPath())
	}
	if err != nil {
		return nil, err
	}
	if err := decodeShared(b, &c.Shared); err != nil {
		return nil, fmt.Errorf("%s: %w", c.SharedPath(), err)
	}
	if c.Shared.Cluster == "" {
		c.Shared.Cluster = cluster
	}
	if b, err := os.ReadFile(c.LocalPath()); err == nil {
		if err := yaml.Unmarshal(b, &c.Local); err != nil {
			return nil, fmt.Errorf("%s: %w", c.LocalPath(), err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return c, nil
}

// decodeShared reads cluster.yaml strictly: an unknown field (a credential or key path someone
// added by hand) is refused, and so is anything that looks like a private key.
func decodeShared(b []byte, s *Shared) error {
	if secretLooking(b) {
		return errors.New("it holds a private key or token: cluster.yaml is shared and must hold no secret (move it to local.yaml)")
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(s); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w (cluster.yaml holds cluster, server, ca, hosts and admins only: credentials and keys go in local.yaml)", err)
	}
	for _, a := range s.Admins {
		for _, k := range a.SSHKeys {
			if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k)); err != nil {
				return fmt.Errorf("admin %s: %q is not an SSH public key (an authorized_keys line)", a.Name, short(k))
			}
		}
	}
	return nil
}

// secretLooking reports whether text holds a private key or a bearer token.
func secretLooking(b []byte) bool {
	t := string(b)
	return strings.Contains(t, "PRIVATE KEY") || strings.Contains(t, "KVR1-") || strings.Contains(t, "kvt_")
}

func short(s string) string {
	if len(s) > 24 {
		return s[:24] + "…"
	}
	return s
}

// SharedPath and LocalPath are the two files' paths.
func (c *Config) SharedPath() string { return filepath.Join(c.dir, SharedFile) }

// LocalPath is local.yaml's path.
func (c *Config) LocalPath() string { return filepath.Join(c.dir, LocalFile) }

// Folder is the cluster's folder.
func (c *Config) Folder() string { return c.dir }

// File resolves a file name from local.yaml (relative to the folder).
func (c *Config) File(name string) string {
	if name == "" || filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(c.dir, name)
}

// Cluster is the cluster's name.
func (c *Config) Cluster() string { return c.Shared.Cluster }

// Server is the control planes' API addresses, comma-separated.
func (c *Config) Server() string { return c.Shared.Server }

// CAPEM is the cluster CA certificate.
func (c *Config) CAPEM() []byte { return []byte(c.Shared.CA) }

// SSHKey is this admin's private key path ("" when local.yaml names none).
func (c *Config) SSHKey() string { return c.Local.SSHKey }

// Save writes both files and the .gitignore: folder 0700, local.yaml 0600, cluster.yaml 0644.
func (c *Config) Save() error {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(c.dir, 0o700); err != nil {
		return err
	}
	shared, err := yaml.Marshal(c.Shared)
	if err != nil {
		return err
	}
	if secretLooking(shared) {
		return errors.New("refusing to write a secret into cluster.yaml")
	}
	local, err := yaml.Marshal(c.Local)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{{c.SharedPath(), shared, 0o644}, {c.LocalPath(), local, 0o600}, {filepath.Join(c.dir, ".gitignore"), []byte(gitignore), 0o644}} {
		if err := writeAtomic(f.path, f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// WriteCredentials stores the cluster CA (shared: it's public) and this admin's certificate and
// key (local) and points local.yaml at them.
func (c *Config) WriteCredentials(caPEM, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	c.Shared.CA = string(caPEM)
	c.Local.Certificate, c.Local.Key = "admin.crt", "admin.key"
	if err := writeAtomic(c.File(c.Local.Certificate), certPEM, 0o600); err != nil {
		return err
	}
	return writeAtomic(c.File(c.Local.Key), keyPEM, 0o600)
}

// Context is the config as a kvo context (the certificate's absolute paths), for what both tools
// share: renewing the certificate in place.
func (c *Config) Context() kvoconfig.Context {
	return kvoconfig.Context{Server: c.Shared.Server, Certificate: c.File(c.Local.Certificate), Key: c.File(c.Local.Key)}
}

// Client is an API client as this admin. The certificate is renewed in the folder when it's due.
func (c *Config) Client() (*client.Client, error) {
	if c.Local.Certificate == "" || c.Local.Key == "" {
		return nil, fmt.Errorf("cluster %s: no admin credential on this machine (%s names none): kvoadm users resign ADDRESS --name YOU writes one",
			c.Cluster(), c.LocalPath())
	}
	if c.Shared.CA == "" {
		return nil, fmt.Errorf("cluster %s: %s has no ca", c.Cluster(), c.SharedPath())
	}
	return kvoconfig.CertClient(c.Cluster(), c.Context(), c.CAPEM())
}

// AddServer adds a control plane's API URL to the server list. It reports whether it was new.
func (c *Config) AddServer(url string) bool {
	servers := client.SplitServers(c.Shared.Server)
	if slices.Contains(servers, url) {
		return false
	}
	c.Shared.Server = strings.Join(append(servers, url), ",")
	return true
}

// Addresses is a host's addresses in the order to try: this machine's, then the team's.
func (c *Config) Addresses(host string) []string {
	var out []string
	for _, a := range append(slices.Clone(c.Local.Hosts[host].Addresses), c.Shared.Hosts[host].Addresses...) {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// HasHost reports whether either file names the host.
func (c *Config) HasHost(host string) bool {
	_, s := c.Shared.Hosts[host]
	_, l := c.Local.Hosts[host]
	return s || l
}

// HostKey is the SSH host key this machine pinned for a host.
func (c *Config) HostKey(host string) string { return c.Local.Hosts[host].HostKey }

// AddAddresses appends addresses to a host's list: the team's (shared) or this machine's (local).
// It reports the ones it added.
func (c *Config) AddAddresses(host string, local bool, addrs ...string) ([]string, error) {
	for _, a := range addrs {
		if _, err := ParseAddress(a, "root", 22); err != nil {
			return nil, err
		}
	}
	var added []string
	if local {
		h := c.Local.Hosts[host]
		h.Addresses, added = appendNew(h.Addresses, addrs)
		c.setLocal(host, h)
	} else {
		h := c.Shared.Hosts[host]
		h.Addresses, added = appendNew(h.Addresses, addrs)
		c.setShared(host, h)
	}
	return added, nil
}

// RemoveAddresses takes addresses off a host's lists, both files. It reports the ones removed.
func (c *Config) RemoveAddresses(host string, addrs ...string) []string {
	var removed []string
	drop := func(list []string) []string {
		return slices.DeleteFunc(slices.Clone(list), func(a string) bool {
			if slices.Contains(addrs, a) {
				if !slices.Contains(removed, a) {
					removed = append(removed, a)
				}
				return true
			}
			return false
		})
	}
	if h, ok := c.Local.Hosts[host]; ok {
		h.Addresses = drop(h.Addresses)
		c.setLocal(host, h)
	}
	if h, ok := c.Shared.Hosts[host]; ok {
		h.Addresses = drop(h.Addresses)
		c.setShared(host, h)
	}
	return removed
}

// RecordHost notes a host kvoadm just set up: the address it used goes first in the team's list
// when it's new there, and the host key it pinned is kept on this machine.
func (c *Config) RecordHost(host, addr, hostKey string) {
	if addr != "" {
		h := c.Shared.Hosts[host]
		if !slices.Contains(h.Addresses, addr) {
			h.Addresses = append([]string{addr}, h.Addresses...)
		}
		c.setShared(host, h)
	}
	if hostKey != "" {
		h := c.Local.Hosts[host]
		h.HostKey = hostKey
		c.setLocal(host, h)
	}
}

// ForgetHost drops a host from both files (kvoadm host remove).
func (c *Config) ForgetHost(host string) {
	delete(c.Shared.Hosts, host)
	delete(c.Local.Hosts, host)
}

// HostFor finds the host one of whose addresses is addr (with or without user and port).
func (c *Config) HostFor(addr string) (string, bool) {
	want, err := ParseAddress(addr, "", 0)
	if err != nil {
		return "", false
	}
	names := map[string]bool{}
	for n := range c.Shared.Hosts {
		names[n] = true
	}
	for n := range c.Local.Hosts {
		names[n] = true
	}
	for name := range names {
		for _, a := range c.Addresses(name) {
			t, err := ParseAddress(a, "", 0)
			if err == nil && t.Host == want.Host && (want.Port == 0 || t.Port == 0 || t.Port == want.Port) {
				return name, true
			}
		}
	}
	return "", false
}

// SetAdmin adds an admin or replaces their keys. Each key must be an SSH public key.
func (c *Config) SetAdmin(name string, keys ...string) error {
	if name == "" || strings.ContainsAny(name, " \t\n:") {
		return fmt.Errorf("admin name %q: one word", name)
	}
	for _, k := range keys {
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k)); err != nil {
			return fmt.Errorf("admin %s: %q is not an SSH public key (an authorized_keys line)", name, short(k))
		}
		if secretLooking([]byte(k)) {
			return fmt.Errorf("admin %s: that's a private key: give the public one (.pub)", name)
		}
	}
	for i := range c.Shared.Admins {
		if c.Shared.Admins[i].Name == name {
			c.Shared.Admins[i].SSHKeys = keys
			return nil
		}
	}
	c.Shared.Admins = append(c.Shared.Admins, Admin{Name: name, SSHKeys: keys})
	return nil
}

// RemoveAdmin drops an admin. It reports whether there was one.
func (c *Config) RemoveAdmin(name string) bool {
	n := len(c.Shared.Admins)
	c.Shared.Admins = slices.DeleteFunc(c.Shared.Admins, func(a Admin) bool { return a.Name == name })
	return len(c.Shared.Admins) != n
}

func (c *Config) setShared(name string, h SharedHost) {
	if c.Shared.Hosts == nil {
		c.Shared.Hosts = map[string]SharedHost{}
	}
	if len(h.Addresses) == 0 {
		delete(c.Shared.Hosts, name)
		return
	}
	c.Shared.Hosts[name] = h
}

func (c *Config) setLocal(name string, h LocalHost) {
	if c.Local.Hosts == nil {
		c.Local.Hosts = map[string]LocalHost{}
	}
	if len(h.Addresses) == 0 && h.HostKey == "" {
		delete(c.Local.Hosts, name)
		return
	}
	c.Local.Hosts[name] = h
}

func appendNew(list, add []string) ([]string, []string) {
	var added []string
	for _, a := range add {
		if !slices.Contains(list, a) {
			list = append(list, a)
			added = append(added, a)
		}
	}
	return list, added
}

// Target is one way to reach a host over SSH.
type Target struct {
	User string
	Host string // an IP or a hostname
	Port int
}

func (t Target) String() string {
	return t.User + "@" + net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// ParseAddress reads [USER@]ADDRESS[:PORT], filling the user and port it lacks with the
// defaults. An IPv6 address with a port is written [ADDR]:PORT. Pure.
func ParseAddress(s, defUser string, defPort int) (Target, error) {
	t := Target{User: defUser, Port: defPort}
	s = strings.TrimSpace(s)
	if u, rest, ok := strings.Cut(s, "@"); ok {
		if u == "" {
			return t, fmt.Errorf("address %q: empty user", s)
		}
		t.User, s = u, rest
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return t, fmt.Errorf("address %q: bad port", s)
		}
		t.Host, t.Port = h, n
	} else {
		t.Host = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	}
	if t.Host == "" || strings.ContainsAny(t.Host, " /@") {
		return t, fmt.Errorf("address %q: want [USER@]ADDRESS[:PORT] (an IP or a hostname)", s)
	}
	return t, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
