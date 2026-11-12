// Package sshboot sets up a fresh machine over SSH, once, the way research E016–E018 proved:
//
//  1. Host key first: pinned (--host-key SHA256:…) or shown and confirmed on first contact, through a
//     probe connection that sends no credentials. Only then is the password read.
//  2. The root password (if that's what the provider gave) is used for one connection, pinned to the
//     confirmed key, and never stored, logged or put in a command.
//  3. Harden: install an SSH key, switch sshd to key-only, rotate the root password to a random value
//     nobody ever sees.
//  4. Install binaries only after their signature verifies on the host itself.
//
// Every command runs through Conn.Run; file contents always travel on stdin, never in arguments.
package sshboot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// HostKeyPolicy decides which host key to trust.
type HostKeyPolicy struct {
	// Pin is the expected fingerprint (SHA256:…). If set, any other key aborts the connection.
	Pin string
	// Confirm is asked on first contact when Pin is empty. Returning false aborts before any
	// credential is used.
	Confirm func(keyType, fingerprint string) bool
	// Algorithm is the host key type to ask for, so a provider's ED25519 fingerprint can match
	// (default ed25519; E016 found Go otherwise negotiates ECDSA on Ubuntu 24.04).
	Algorithm string
}

// Auth is how to log in: a key, or a password read only after the host key is trusted.
type Auth struct {
	Signer   ssh.Signer
	Password func() (string, error)
}

// Target is where to connect.
type Target struct {
	Addr string // host:port
	User string // default root
}

// Conn is an SSH connection to the machine being set up.
type Conn struct {
	c           *ssh.Client
	Fingerprint string // the host key it's pinned to
	// Sudo runs every command through `sudo -n` (logged in as a user with passwordless sudo, e.g.
	// a cloud image's default user, instead of root).
	Sudo bool
}

// ErrHostKey: the host key wasn't the pinned one, or wasn't confirmed.
var ErrHostKey = errors.New("host key not trusted")

func (p HostKeyPolicy) algorithm() string {
	if p.Algorithm != "" {
		return p.Algorithm
	}
	return ssh.KeyAlgoED25519
}

func pinned(fp string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, k ssh.PublicKey) error {
		if got := ssh.FingerprintSHA256(k); got != fp {
			return fmt.Errorf("%w: got %s, expected %s", ErrHostKey, got, fp)
		}
		return nil
	}
}

func dial(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	}
	cc, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(cc, chans, reqs), nil
}

// Connect establishes a connection whose host key is trusted before any credential is used.
func Connect(ctx context.Context, t Target, policy HostKeyPolicy, auth Auth) (*Conn, error) {
	if t.User == "" {
		t.User = "root"
	}
	fp := policy.Pin
	if fp == "" {
		if policy.Confirm == nil {
			return nil, fmt.Errorf("%w: no pinned fingerprint and no way to confirm one", ErrHostKey)
		}
		// Probe with no credentials: we only want the server's key. The handshake gets far enough to
		// show it, then fails auth (or our callback stops it) — either way nothing secret was sent.
		var seen ssh.PublicKey
		probe := &ssh.ClientConfig{
			User:              t.User,
			HostKeyAlgorithms: []string{policy.algorithm()},
			Timeout:           15 * time.Second,
			HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
				seen = k
				return errors.New("probe only")
			},
		}
		if c, err := dial(ctx, t.Addr, probe); err == nil {
			_ = c.Close()
		}
		if seen == nil {
			return nil, fmt.Errorf("couldn't read the host key of %s", t.Addr)
		}
		fp = ssh.FingerprintSHA256(seen)
		if !policy.Confirm(seen.Type(), fp) {
			return nil, fmt.Errorf("%w: %s not confirmed", ErrHostKey, fp)
		}
	}
	var methods []ssh.AuthMethod
	switch {
	case auth.Signer != nil:
		methods = append(methods, ssh.PublicKeys(auth.Signer))
	case auth.Password != nil:
		// Read lazily: only after the host key passed the callback for THIS connection.
		methods = append(methods, ssh.PasswordCallback(auth.Password))
	default:
		return nil, errors.New("no SSH key and no password")
	}
	c, err := dial(ctx, t.Addr, &ssh.ClientConfig{
		User:              t.User,
		Auth:              methods,
		HostKeyCallback:   pinned(fp),
		HostKeyAlgorithms: []string{policy.algorithm()},
		Timeout:           15 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return &Conn{c: c, Fingerprint: fp}, nil
}

// Close closes the connection.
func (c *Conn) Close() error { return c.c.Close() }

// Run runs a shell command on the host, with stdin, and returns its combined output.
func (c *Conn) Run(ctx context.Context, cmd string, stdin []byte) ([]byte, error) {
	s, err := c.c.NewSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	if stdin != nil {
		s.Stdin = bytes.NewReader(stdin)
	}
	type result struct {
		out []byte
		err error
	}
	if c.Sudo {
		cmd = "sudo -n sh -c " + Quote(cmd)
	}
	done := make(chan result, 1)
	go func() {
		out, err := s.CombinedOutput(cmd) // stdout and stderr through one synchronized writer
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return r.out, fmt.Errorf("%s: %w: %s", firstWord(cmd), r.err, strings.TrimSpace(string(r.out)))
		}
		return r.out, nil
	case <-ctx.Done():
		_ = s.Signal(ssh.SIGKILL)
		return nil, ctx.Err()
	}
}

func firstWord(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return "command"
	}
	return f[0]
}

// Quote quotes a string for a POSIX shell.
func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// Upload writes data to path on the host (atomically, via a temp file), with mode.
func (c *Conn) Upload(ctx context.Context, path string, data []byte, mode uint32) error {
	tmp := path + ".kvo-tmp"
	cmd := fmt.Sprintf("umask 077 && cat > %s && chmod %04o %s && mv -f %s %s", Quote(tmp), mode, Quote(tmp), Quote(tmp), Quote(path))
	_, err := c.Run(ctx, cmd, data)
	return err
}

// SSHDDropIn makes root key-only (E016).
const SSHDDropIn = `# written by kvoadm: key-only root login from now on
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
`

// RotateRootPassword replaces root's password with a random value generated on the host and never
// transmitted (E017).
const RotateRootPassword = `set -o pipefail; head -c 48 /dev/urandom | base64 -w0 | sed 's/^/root:/' | chpasswd`

// Harden installs authorizedKey for root, switches sshd to key-only, and rotates the root password.
func (c *Conn) Harden(ctx context.Context, authorizedKey []byte) error {
	steps := []struct {
		what, cmd string
		stdin     []byte
	}{
		// Idempotent: adds the key only if it isn't there yet (the key travels on stdin).
		{"install SSH key", `umask 077 && mkdir -p /root/.ssh && touch /root/.ssh/authorized_keys && ` +
			`k=$(cat) && (grep -qxF "$k" /root/.ssh/authorized_keys || printf '%s\n' "$k" >> /root/.ssh/authorized_keys)`,
			bytes.TrimSpace(authorizedKey)},
		{"sshd key-only", "cat > /etc/ssh/sshd_config.d/00-kevaso.conf && sshd -t && (systemctl reload ssh || systemctl reload sshd)", []byte(SSHDDropIn)},
		{"rotate root password", "bash -c " + Quote(RotateRootPassword), nil},
	}
	for _, s := range steps {
		if _, err := c.Run(ctx, s.cmd, s.stdin); err != nil {
			return fmt.Errorf("%s: %w", s.what, err)
		}
	}
	return nil
}

// Paths on the host.
const (
	SigningKeyPath = "/etc/kevaso/release.pub" // pinned at bootstrap
	StagingDir     = "/var/lib/kevaso/staging"
	InstallDir     = "/usr/local/bin"
)

// ErrSignature: the binary didn't verify on the host; nothing was installed.
var ErrSignature = errors.New("signature check failed on the host")

// InstallBinary pushes a binary and its ed25519 signature, verifies it on the host with the pinned
// public key (stock openssl, E018), and only then installs it to InstallDir/name.
func (c *Conn) InstallBinary(ctx context.Context, name string, data, sig []byte) error {
	staged := StagingDir + "/" + name
	if _, err := c.Run(ctx, "mkdir -p "+StagingDir+" && chmod 0700 "+StagingDir, nil); err != nil {
		return err
	}
	if err := c.Upload(ctx, staged, data, 0o600); err != nil {
		return err
	}
	if err := c.Upload(ctx, staged+".sig", sig, 0o600); err != nil {
		return err
	}
	verify := fmt.Sprintf("openssl pkeyutl -verify -pubin -inkey %s -rawin -in %s -sigfile %s", SigningKeyPath, Quote(staged), Quote(staged+".sig"))
	if _, err := c.Run(ctx, verify, nil); err != nil {
		_, _ = c.Run(ctx, "rm -f "+Quote(staged)+" "+Quote(staged+".sig"), nil)
		return fmt.Errorf("%s: %w", name, ErrSignature)
	}
	_, err := c.Run(ctx, fmt.Sprintf("install -m 0755 %s %s/%s && rm -f %s %s", Quote(staged), InstallDir, name, Quote(staged), Quote(staged+".sig")), nil)
	return err
}

// PinSigningKey writes the public key binaries must verify against.
func (c *Conn) PinSigningKey(ctx context.Context, pubPEM []byte) error {
	if _, err := c.Run(ctx, "mkdir -p /etc/kevaso", nil); err != nil {
		return err
	}
	return c.Upload(ctx, SigningKeyPath, pubPEM, 0o644)
}

// InstallUnit writes a systemd unit and enables and starts it.
func (c *Conn) InstallUnit(ctx context.Context, name string, unit []byte) error {
	if err := c.Upload(ctx, "/etc/systemd/system/"+name, unit, 0o644); err != nil {
		return err
	}
	_, err := c.Run(ctx, "systemctl daemon-reload && systemctl enable --now "+Quote(name)+" && systemctl restart "+Quote(name), nil)
	return err
}
