package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/internal/sshboot"
	"kevaso.com/core/testbed/remote"
)

// labHost is the EPYC (or whatever LAB_HOST names), reached as root through sudo.
type labHost struct {
	d   *remote.Driver
	cfg remote.Config
}

func dialHost(ctx context.Context) (*labHost, error) {
	target := os.Getenv("LAB_HOST")
	if target == "" {
		target = "ubuntu@54.39.243.98"
	}
	key := os.Getenv("LAB_SSH_KEY")
	if key == "" {
		key = "~/.ssh/kevaso-testbed_ed25519"
	}
	if strings.HasPrefix(key, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		key = filepath.Join(home, key[2:])
	}
	user, addr, port, err := remote.ParseTarget(target)
	if err != nil {
		return nil, fmt.Errorf("LAB_HOST: %w", err)
	}
	ext := strings.TrimSpace(os.Getenv("LAB_EXTERNAL_IP"))
	if ext == "" {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
			ext = ip.To4().String()
		}
	}
	if ext == "" {
		return nil, errors.New("LAB_HOST is a name: set LAB_EXTERNAL_IP to the host's public IPv4")
	}
	pin, err := hostPin(addr)
	if err != nil {
		return nil, err
	}
	cfg := remote.Config{User: user, Address: addr, Port: port, KeyFile: key, HostKey: pin, ExternalIP: ext}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	d := remote.New(cfg)
	if _, err := d.Run(ctx, "true", nil); err != nil {
		return nil, fmt.Errorf("lab host: %s", scrub(err.Error()))
	}
	return &labHost{d: d, cfg: cfg}, nil
}

// hostPin is LAB_HOSTKEY, or the ED25519 key already in known_hosts. A host that isn't there
// is refused: this does not trust a key the network offers.
func hostPin(addr string) (string, error) {
	if p := strings.TrimSpace(os.Getenv("LAB_HOSTKEY")); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	known := filepath.Join(home, ".ssh", "known_hosts")
	out, err := exec.Command("ssh-keygen", "-F", addr, "-f", known).Output()
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("no known host key for %s (%s); set LAB_HOSTKEY to the SHA256: fingerprint read on the console", addr, known)
	}
	var line string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.Contains(l, "ssh-ed25519") {
			line = l
			break
		}
	}
	if line == "" {
		return "", fmt.Errorf("known_hosts has no ed25519 key for %s; set LAB_HOSTKEY", addr)
	}
	cmd := exec.Command("ssh-keygen", "-lf", "-")
	cmd.Stdin = strings.NewReader(line + "\n")
	out, err = cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ssh-keygen -lf: %w", err)
	}
	f := strings.Fields(string(out))
	if len(f) < 2 || !strings.HasPrefix(f[1], "SHA256:") {
		return "", fmt.Errorf("ssh-keygen -lf returned %q", strings.TrimSpace(string(out)))
	}
	return f[1], nil
}

func (h *labHost) run(ctx context.Context, script string) (string, error) {
	out, err := h.d.Run(ctx, script, nil)
	if err != nil {
		return out, errors.New(scrub(err.Error()))
	}
	return out, nil
}

func (h *labHost) upload(ctx context.Context, path string, data []byte, mode uint32) error {
	tmp := path + ".tmp"
	cmd := fmt.Sprintf("umask 077 && cat > %s && chmod %04o %s && mv -f %s %s",
		sshboot.Quote(tmp), mode, sshboot.Quote(tmp), sshboot.Quote(tmp), sshboot.Quote(path))
	if _, err := h.d.Run(ctx, cmd, data); err != nil {
		return errors.New(scrub(err.Error()))
	}
	return nil
}

func (h *labHost) Close() error { return h.d.Close() }

// probeHostKey reads the VM's ED25519 host key and does not log in.
func probeHostKey(addr string) (string, error) {
	var pub ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:              "ubuntu",
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           5 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			pub = k
			return errors.New("probe")
		},
	}
	c, err := ssh.Dial("tcp", addr, cfg)
	if c != nil {
		_ = c.Close()
	}
	if pub == nil {
		return "", err
	}
	return ssh.FingerprintSHA256(pub), nil
}

// vmRun runs a script as ubuntu on a node VM, through a forwarded port, pinned to pin.
func vmRun(ctx context.Context, addr, keyPath, pin, script string) (string, error) {
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return "", err
	}
	cfg := &ssh.ClientConfig{
		User:              "ubuntu",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           10 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if got := ssh.FingerprintSHA256(k); got != pin {
				return fmt.Errorf("host key %s, want %s", got, pin)
			}
			return nil
		},
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	c, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		_ = nc.Close()
		return "", err
	}
	client := ssh.NewClient(c, chans, reqs)
	defer func() { _ = client.Close() }()
	s, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = s.Close() }()
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := s.CombinedOutput(script)
		done <- result{out, err}
	}()
	select {
	case <-ctx.Done():
		_ = s.Close()
		return "", ctx.Err()
	case r := <-done:
		if r.err != nil {
			return string(r.out), fmt.Errorf("%w: %s", r.err, strings.TrimSpace(string(r.out)))
		}
		return string(r.out), nil
	}
}

func parseFacts(out string) map[string][]string {
	m := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || k == "" {
			continue
		}
		m[k] = append(m[k], v)
	}
	return m
}

func cut2(s string) (a, b string, ok bool) {
	a, b, ok = strings.Cut(s, " ")
	return a, b, ok
}
