// Package remote is the testbed driver for a machine that already exists: one dedicated test
// machine (bare metal with KVM and a real external IP), reached over SSH with one key and a host
// key pinned out of band. It creates nothing. "Deleting" a machine is resetting it to clean: every
// unit, binary, data directory, firewall table, link, logical volume, package, container and image
// Kevaso put there is removed, and a checklist then fails loudly if anything is left (reset.go).
//
// The machine comes from the environment (see FromEnv): no address, key or fingerprint is ever
// written in code, and nothing is sent to the machine until its host key matches the pin (there is
// no trust on first use).
package remote

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/internal/sshboot"
	"kevaso.com/core/testbed"
)

// The environment variables that describe the machine.
const (
	EnvHost       = "KEVASO_METAL_HOST"        // [USER@]ADDRESS[:PORT]: the SSH target (user root by default)
	EnvKey        = "KEVASO_METAL_KEY"         // the private key file that logs in (and nothing else is tried)
	EnvHostKey    = "KEVASO_METAL_HOSTKEY"     // SHA256:… of the machine's ED25519 host key, read out of band
	EnvExternalIP = "KEVASO_METAL_EXTERNAL_IP" // the machine's address reachable from the internet
	EnvInternalIP = "KEVASO_METAL_INTERNAL_IP" // optional: its address on a private network
	EnvHostname   = "KEVASO_METAL_HOSTNAME"    // optional: a public DNS name for the external IP (certificate tests)
)

// Config is the machine.
type Config struct {
	User       string
	Address    string // host name or IP, as SSH dials it
	Port       int
	KeyFile    string
	HostKey    string // SHA256:…
	ExternalIP string
	InternalIP string // "" when the machine has none
	Hostname   string // "" when none was given
}

// ErrNotConfigured: the environment doesn't name a machine (tests skip on it).
var ErrNotConfigured = errors.New("no test machine configured")

// FromEnv reads the machine from the environment. Missing required variables give an error
// wrapping ErrNotConfigured that names them; present but malformed ones give another error.
func FromEnv(getenv func(string) string) (Config, error) {
	var missing []string
	need := func(name string) string {
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			missing = append(missing, name)
		}
		return v
	}
	host, key, hk, ext := need(EnvHost), need(EnvKey), need(EnvHostKey), need(EnvExternalIP)
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("%w: set %s (see test/e2e/METAL.md)", ErrNotConfigured, strings.Join(missing, ", "))
	}
	c := Config{KeyFile: key, HostKey: hk, ExternalIP: ext,
		InternalIP: strings.TrimSpace(getenv(EnvInternalIP)), Hostname: strings.TrimSpace(getenv(EnvHostname))}
	var err error
	if c.User, c.Address, c.Port, err = ParseTarget(host); err != nil {
		return Config{}, fmt.Errorf("%s: %w", EnvHost, err)
	}
	return c, c.Validate()
}

// ParseTarget splits [USER@]ADDRESS[:PORT] (user root, port 22 by default).
func ParseTarget(s string) (user, addr string, port int, err error) {
	user, addr = "root", s
	if u, rest, ok := strings.Cut(s, "@"); ok {
		user, addr = u, rest
	}
	port = 22
	if h, p, e := net.SplitHostPort(addr); e == nil {
		addr = h
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return "", "", 0, fmt.Errorf("port %q", p)
		}
	}
	if user == "" || addr == "" || strings.ContainsAny(addr, " /@") {
		return "", "", 0, fmt.Errorf("%q: want [USER@]ADDRESS[:PORT]", s)
	}
	return user, addr, port, nil
}

// Validate checks the config's shape (not the machine).
func (c Config) Validate() error {
	var errs []error
	if !strings.HasPrefix(c.HostKey, "SHA256:") || len(c.HostKey) < len("SHA256:")+40 {
		errs = append(errs, fmt.Errorf("%s %q: want the SHA256:… fingerprint of the ED25519 host key (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub, read on the provider's console)", EnvHostKey, c.HostKey))
	}
	ext, err := netip.ParseAddr(c.ExternalIP)
	if err != nil || !ext.Is4() {
		errs = append(errs, fmt.Errorf("%s %q: want an IPv4 address", EnvExternalIP, c.ExternalIP))
	} else if ext.IsPrivate() || ext.IsLoopback() || ext.IsLinkLocalUnicast() || ext.IsUnspecified() {
		errs = append(errs, fmt.Errorf("%s %s: not a public address", EnvExternalIP, c.ExternalIP))
	}
	if c.InternalIP != "" {
		in, err := netip.ParseAddr(c.InternalIP)
		switch {
		case err != nil || !in.Is4():
			errs = append(errs, fmt.Errorf("%s %q: want an IPv4 address", EnvInternalIP, c.InternalIP))
		case in == ext:
			errs = append(errs, fmt.Errorf("%s: the same as the external IP (a machine with one address has only an external one)", EnvInternalIP))
		}
	}
	if c.Hostname != "" && (strings.ContainsAny(c.Hostname, " /:*") || !strings.Contains(c.Hostname, ".")) {
		errs = append(errs, fmt.Errorf("%s %q: want a DNS name", EnvHostname, c.Hostname))
	}
	if c.KeyFile == "" {
		errs = append(errs, fmt.Errorf("%s: required", EnvKey))
	}
	return errors.Join(errs...)
}

// SSHTarget is "USER@ADDRESS" for kvoadm (the port goes in --ssh-port).
func (c Config) SSHTarget() string { return c.User + "@" + c.Address }

// Driver is the one machine. It implements testbed.Driver and testbed.SSHAccess.
type Driver struct {
	Config Config

	mu   sync.Mutex
	conn *sshboot.Conn
}

// New returns a driver for the machine.
func New(c Config) *Driver { return &Driver{Config: c} }

// connect returns the connection, dialing it (host key checked against the pin before the key is
// offered) when there is none.
func (d *Driver) connect(ctx context.Context) (*sshboot.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		return d.conn, nil
	}
	pem, err := os.ReadFile(d.Config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvKey, err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (an unencrypted key: the tests can't ask for a passphrase)", EnvKey, err)
	}
	c, err := sshboot.Connect(ctx, sshboot.Target{Addr: net.JoinHostPort(d.Config.Address, strconv.Itoa(d.Config.Port)), User: d.Config.User},
		sshboot.HostKeyPolicy{Pin: d.Config.HostKey}, sshboot.Auth{Signer: signer})
	if err != nil {
		return nil, err
	}
	c.Sudo = d.Config.User != "root"
	d.conn = c
	return c, nil
}

// drop forgets the connection after a failure that wasn't the command's own exit status, so the
// next call dials again.
func (d *Driver) drop(c *sshboot.Conn, err error) {
	var exit *ssh.ExitError
	if err == nil || errors.As(err, &exit) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == c {
		_ = c.Close() // already broken
		d.conn = nil
	}
}

// Run runs a shell script as root and returns its combined output.
func (d *Driver) Run(ctx context.Context, script string, stdin []byte) (string, error) {
	c, err := d.connect(ctx)
	if err != nil {
		return "", err
	}
	out, err := c.Run(ctx, script, stdin)
	d.drop(c, err)
	return string(out), err
}

// RunAsLogin runs a script as the login user, without sudo (what sudo would drop, such as
// SSH_CLIENT, is still there). For a root login it is the same as Run.
func (d *Driver) RunAsLogin(ctx context.Context, script string) (string, error) {
	c, err := d.connect(ctx)
	if err != nil {
		return "", err
	}
	plain := *c
	plain.Sudo = false
	out, err := plain.Run(ctx, script, nil)
	d.drop(c, err)
	return string(out), err
}

// Close closes the connection.
func (d *Driver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil {
		return nil
	}
	err := d.conn.Close()
	d.conn = nil
	return err
}

// Create implements testbed.Driver: the machine exists; it gets a testbed name and is reached
// once, which checks the host key.
func (d *Driver) Create(ctx context.Context, run testbed.RunID, spec testbed.Spec) (testbed.Machine, error) {
	if err := run.Validate(); err != nil {
		return testbed.Machine{}, err
	}
	if err := spec.Validate(); err != nil {
		return testbed.Machine{}, err
	}
	if _, err := d.Run(ctx, "true", nil); err != nil {
		return testbed.Machine{}, err
	}
	return testbed.Machine{Name: testbed.MachineName(run, spec.Role), Run: run, Role: spec.Role}, nil
}

// Exec implements testbed.Driver: the argv, quoted, as root.
func (d *Driver) Exec(ctx context.Context, _ testbed.Machine, cmd ...string) (string, error) {
	if len(cmd) == 0 {
		return "", errors.New("exec: no command")
	}
	return d.Run(ctx, Join(cmd), nil)
}

// Join quotes an argv for a POSIX shell.
func Join(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = sshboot.Quote(a)
	}
	return strings.Join(q, " ")
}

// CopyTo implements testbed.Driver: the file travels on stdin and lands atomically, with the
// local file's mode.
func (d *Driver) CopyTo(ctx context.Context, _ testbed.Machine, local, remote string) error {
	info, err := os.Stat(local)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	c, err := d.connect(ctx)
	if err != nil {
		return err
	}
	err = c.Upload(ctx, remote, data, uint32(info.Mode().Perm()))
	d.drop(c, err)
	return err
}

// Delete implements testbed.Driver: the machine is reset to clean (Reset), never destroyed.
func (d *Driver) Delete(ctx context.Context, _ testbed.Machine) error {
	return d.Reset(ctx)
}

// List implements testbed.Driver: the driver creates nothing, so there are never leftovers to sweep.
func (d *Driver) List(context.Context) ([]testbed.Machine, error) { return nil, nil }

// SSH implements testbed.SSHAccess.
func (d *Driver) SSH(context.Context, testbed.Machine) (testbed.SSHInfo, error) {
	return testbed.SSHInfo{Host: d.Config.Address, Port: d.Config.Port, User: d.Config.User, KeyFile: d.Config.KeyFile}, nil
}

var (
	_ testbed.Driver    = (*Driver)(nil)
	_ testbed.SSHAccess = (*Driver)(nil)
)
