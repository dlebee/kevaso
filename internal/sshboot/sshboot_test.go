package sshboot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const rootPassword = "provider-given-password"

// fakeHost is an in-process SSH server: password or key auth for root, and exec requests answered by
// a handler that sees each command and its stdin. It records everything it was sent.
type fakeHost struct {
	t       *testing.T
	addr    string
	keys    []ssh.Signer // host key per connection; the last one repeats
	conns   atomic.Int32
	allowed ssh.PublicKey // client key accepted after Harden
	handler func(cmd string, stdin []byte) (string, int)

	mu       sync.Mutex
	commands []string
	stdins   [][]byte
	authSeen []string // "password:<value>" or "key"
}

func newSigner(t *testing.T) ssh.Signer {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startFakeHost(t *testing.T, keys ...ssh.Signer) *fakeHost {
	h := &fakeHost{t: t, keys: keys, handler: func(string, []byte) (string, int) { return "", 0 }}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	h.addr = l.Addr().String()
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go h.serve(nc)
		}
	}()
	return h
}

func (h *fakeHost) serve(nc net.Conn) {
	defer func() { _ = nc.Close() }()
	n := int(h.conns.Add(1)) - 1
	if n >= len(h.keys) {
		n = len(h.keys) - 1
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			h.mu.Lock()
			h.authSeen = append(h.authSeen, "password:"+string(pw))
			h.mu.Unlock()
			if string(pw) == rootPassword {
				return nil, nil
			}
			return nil, errors.New("bad password")
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.allowed != nil && string(k.Marshal()) == string(h.allowed.Marshal()) {
				h.authSeen = append(h.authSeen, "key")
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	cfg.AddHostKey(h.keys[n])
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		go h.session(ch, creqs)
	}
}

func (h *fakeHost) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
		cmd := string(req.Payload[4 : 4+cmdLen])
		_ = req.Reply(true, nil)
		stdin, _ := io.ReadAll(ch)
		h.mu.Lock()
		h.commands = append(h.commands, cmd)
		h.stdins = append(h.stdins, stdin)
		h.mu.Unlock()
		out, code := h.handler(cmd, stdin)
		_, _ = ch.Write([]byte(out))
		status := make([]byte, 4)
		binary.BigEndian.PutUint32(status, uint32(code))
		_, _ = ch.SendRequest("exit-status", false, status)
		return
	}
}

func (h *fakeHost) seen() ([]string, [][]byte, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.commands...), append([][]byte(nil), h.stdins...), append([]string(nil), h.authSeen...)
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// countingPassword returns the password and counts how many times it was asked for.
func countingPassword(n *atomic.Int32) func() (string, error) {
	return func() (string, error) { n.Add(1); return rootPassword, nil }
}

func TestPinnedKeyConnects(t *testing.T) {
	hk := newSigner(t)
	h := startFakeHost(t, hk)
	var asked atomic.Int32
	c, err := Connect(ctxT(t), Target{Addr: h.addr}, HostKeyPolicy{Pin: ssh.FingerprintSHA256(hk.PublicKey())},
		Auth{Password: countingPassword(&asked)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if asked.Load() != 1 {
		t.Fatalf("password read %d times, want 1", asked.Load())
	}
}

func TestWrongPinAbortsBeforeThePasswordIsRead(t *testing.T) {
	h := startFakeHost(t, newSigner(t))
	var asked atomic.Int32
	_, err := Connect(ctxT(t), Target{Addr: h.addr}, HostKeyPolicy{Pin: "SHA256:not-the-key"}, Auth{Password: countingPassword(&asked)})
	if !errors.Is(err, ErrHostKey) {
		t.Fatalf("want ErrHostKey, got %v", err)
	}
	_, _, auth := h.seen()
	if asked.Load() != 0 || len(auth) != 0 {
		t.Fatalf("password read %d times, server saw %v: nothing may be sent to an untrusted key", asked.Load(), auth)
	}
}

func TestFirstContactConfirm(t *testing.T) {
	hk := newSigner(t)
	for _, accept := range []bool{false, true} {
		h := startFakeHost(t, hk)
		var asked atomic.Int32
		var shown string
		c, err := Connect(ctxT(t), Target{Addr: h.addr}, HostKeyPolicy{Confirm: func(_, fp string) bool { shown = fp; return accept }},
			Auth{Password: countingPassword(&asked)})
		if shown != ssh.FingerprintSHA256(hk.PublicKey()) {
			t.Fatalf("confirm was shown %q", shown)
		}
		_, _, auth := h.seen()
		if !accept {
			if !errors.Is(err, ErrHostKey) || asked.Load() != 0 || len(auth) != 0 {
				t.Fatalf("declined: err %v, password read %d, server saw %v", err, asked.Load(), auth)
			}
			continue
		}
		if err != nil || asked.Load() != 1 || c.Fingerprint != shown {
			t.Fatalf("accepted: err %v, password read %d, pinned %s", err, asked.Load(), c.Fingerprint)
		}
		_ = c.Close()
	}
}

func TestKeySwapAfterConfirmIsRefused(t *testing.T) {
	// The probe sees key A and the operator confirms it; the real connection presents key B (a
	// man in the middle). The password must not be sent.
	h := startFakeHost(t, newSigner(t), newSigner(t))
	var asked atomic.Int32
	_, err := Connect(ctxT(t), Target{Addr: h.addr}, HostKeyPolicy{Confirm: func(string, string) bool { return true }},
		Auth{Password: countingPassword(&asked)})
	if !errors.Is(err, ErrHostKey) || asked.Load() != 0 {
		t.Fatalf("swapped key: err %v, password read %d", err, asked.Load())
	}
	if _, _, auth := h.seen(); len(auth) != 0 {
		t.Fatalf("server saw credentials %v", auth)
	}
}

func connectWithPassword(t *testing.T, h *fakeHost, hk ssh.Signer) *Conn {
	t.Helper()
	var asked atomic.Int32
	c, err := Connect(ctxT(t), Target{Addr: h.addr}, HostKeyPolicy{Pin: ssh.FingerprintSHA256(hk.PublicKey())}, Auth{Password: countingPassword(&asked)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestHardenNeverSendsThePasswordAndThenKeysWork(t *testing.T) {
	hk := newSigner(t)
	h := startFakeHost(t, hk)
	c := connectWithPassword(t, h, hk)
	client := newSigner(t)
	pub := ssh.MarshalAuthorizedKey(client.PublicKey())
	if err := c.Harden(ctxT(t), pub); err != nil {
		t.Fatal(err)
	}
	cmds, stdins, _ := h.seen()
	if len(cmds) != 3 {
		t.Fatalf("%d commands, want 3: %q", len(cmds), cmds)
	}
	if string(stdins[0]) != strings.TrimSpace(string(pub)) || !strings.Contains(cmds[0], "authorized_keys") {
		t.Errorf("key install: cmd %q stdin %q", cmds[0], stdins[0])
	}
	if string(stdins[1]) != SSHDDropIn || !strings.Contains(cmds[1], "sshd -t") {
		t.Errorf("sshd drop-in: cmd %q", cmds[1])
	}
	if !strings.Contains(cmds[2], "chpasswd") || !strings.Contains(cmds[2], "/dev/urandom") {
		t.Errorf("rotation: cmd %q", cmds[2])
	}
	for i := range cmds {
		if strings.Contains(cmds[i], rootPassword) || strings.Contains(string(stdins[i]), rootPassword) {
			t.Fatalf("the root password appeared in command %d", i)
		}
	}
	// After hardening, the key logs in.
	h.mu.Lock()
	h.allowed = client.PublicKey()
	h.mu.Unlock()
	kc, err := Connect(ctxT(t), Target{Addr: h.addr}, HostKeyPolicy{Pin: c.Fingerprint}, Auth{Signer: client})
	if err != nil {
		t.Fatalf("key login: %v", err)
	}
	_ = kc.Close()
}

func TestUploadUsesStdinNotArguments(t *testing.T) {
	hk := newSigner(t)
	h := startFakeHost(t, hk)
	c := connectWithPassword(t, h, hk)
	secretish := "content-that-must-not-be-in-argv"
	if err := c.Upload(ctxT(t), "/etc/kevaso/x.conf", []byte(secretish), 0o600); err != nil {
		t.Fatal(err)
	}
	cmds, stdins, _ := h.seen()
	if strings.Contains(cmds[0], secretish) || string(stdins[0]) != secretish || !strings.Contains(cmds[0], "chmod 0600") {
		t.Fatalf("upload: cmd %q stdin %q", cmds[0], stdins[0])
	}
}

func TestInstallBinaryOnlyAfterTheSignatureVerifies(t *testing.T) {
	for _, verifies := range []bool{false, true} {
		hk := newSigner(t)
		h := startFakeHost(t, hk)
		h.handler = func(cmd string, _ []byte) (string, int) {
			if strings.HasPrefix(cmd, "openssl pkeyutl -verify") && !verifies {
				return "Signature Verification Failure", 1
			}
			return "", 0
		}
		c := connectWithPassword(t, h, hk)
		err := c.InstallBinary(ctxT(t), "kevasod", []byte("binary"), []byte("sig"))
		cmds, _, _ := h.seen()
		installed := false
		for _, cmd := range cmds {
			if strings.HasPrefix(cmd, "install -m 0755") {
				installed = true
			}
		}
		switch {
		case !verifies && (!errors.Is(err, ErrSignature) || installed):
			t.Fatalf("bad signature: err %v, installed %v, cmds %q", err, installed, cmds)
		case verifies && (err != nil || !installed):
			t.Fatalf("good signature: err %v, installed %v", err, installed)
		}
	}
}

func TestRunReportsFailures(t *testing.T) {
	hk := newSigner(t)
	h := startFakeHost(t, hk)
	h.handler = func(string, []byte) (string, int) { return "no such thing", 3 }
	c := connectWithPassword(t, h, hk)
	_, err := c.Run(ctxT(t), "false", nil)
	if err == nil || !strings.Contains(err.Error(), "no such thing") {
		t.Fatalf("failing command: %v", err)
	}
}

func TestSudoWrapsEveryCommand(t *testing.T) {
	hk := newSigner(t)
	h := startFakeHost(t, hk)
	c := connectWithPassword(t, h, hk)
	c.Sudo = true
	if _, err := c.Run(ctxT(t), "systemctl restart kevasod", []byte("in")); err != nil {
		t.Fatal(err)
	}
	cmds, stdins, _ := h.seen()
	if cmds[0] != "sudo -n sh -c 'systemctl restart kevasod'" || string(stdins[0]) != "in" {
		t.Fatalf("sudo command %q, stdin %q", cmds[0], stdins[0])
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{"a": "'a'", "it's": `'it'\''s'`, "$(rm -rf /)": "'$(rm -rf /)'"} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}
