package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/internal/sshboot"
	"kevaso.com/core/testbed"
)

// fakeMachine is an in-process SSH server: key auth for one client key, exec requests answered by
// a handler that sees each command and its stdin. It records everything it was sent, auth
// attempts included.
type fakeMachine struct {
	addr    string
	hostKey ssh.Signer
	client  ssh.PublicKey
	handler func(cmd string, stdin []byte) (string, int)

	mu       sync.Mutex
	commands []string
	stdins   [][]byte
	auths    int
}

func signer(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s, k
}

func startMachine(t *testing.T, client ssh.PublicKey) *fakeMachine {
	t.Helper()
	hk, _ := signer(t)
	m := &fakeMachine{hostKey: hk, client: client, handler: func(string, []byte) (string, int) { return "", 0 }}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	m.addr = l.Addr().String()
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go m.serve(nc)
		}
	}()
	return m
}

func (m *fakeMachine) serve(nc net.Conn) {
	defer func() { _ = nc.Close() }()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			m.mu.Lock()
			m.auths++
			m.mu.Unlock()
			if string(k.Marshal()) == string(m.client.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	cfg.AddHostKey(m.hostKey)
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
		go m.session(ch, creqs)
	}
}

func (m *fakeMachine) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		n := binary.BigEndian.Uint32(req.Payload[:4])
		cmd := string(req.Payload[4 : 4+n])
		_ = req.Reply(true, nil)
		stdin, _ := io.ReadAll(ch)
		m.mu.Lock()
		m.commands = append(m.commands, cmd)
		m.stdins = append(m.stdins, stdin)
		h := m.handler
		m.mu.Unlock()
		out, code := h(cmd, stdin)
		_, _ = ch.Write([]byte(out))
		status := make([]byte, 4)
		binary.BigEndian.PutUint32(status, uint32(code))
		_, _ = ch.SendRequest("exit-status", false, status)
		return
	}
}

func (m *fakeMachine) seen() ([]string, [][]byte, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.commands...), append([][]byte(nil), m.stdins...), m.auths
}

func (m *fakeMachine) setHandler(h func(cmd string, stdin []byte) (string, int)) {
	m.mu.Lock()
	m.handler = h
	m.mu.Unlock()
}

// keyFile writes the client key as an OpenSSH private key file.
func keyFile(t *testing.T, k ed25519.PrivateKey) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(k, "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// newPair is a fake machine and a driver for it, pinned to its host key.
func newPair(t *testing.T, user string) (*fakeMachine, *Driver) {
	t.Helper()
	cs, ck := signer(t)
	m := startMachine(t, cs.PublicKey())
	host, port, _ := net.SplitHostPort(m.addr)
	p, _ := strconv.Atoi(port)
	d := New(Config{User: user, Address: host, Port: p, KeyFile: keyFile(t, ck), HostKey: ssh.FingerprintSHA256(m.hostKey.PublicKey()),
		ExternalIP: "203.0.113.10"})
	t.Cleanup(func() { _ = d.Close() })
	return m, d
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestFromEnv(t *testing.T) {
	env := map[string]string{
		EnvHost: "root@metal.example.net:2222", EnvKey: "/k", EnvHostKey: "SHA256:" + strings.Repeat("A", 43),
		EnvExternalIP: "203.0.113.10",
	}
	get := func(k string) string { return env[k] }
	c, err := FromEnv(get)
	if err != nil {
		t.Fatal(err)
	}
	if c.User != "root" || c.Address != "metal.example.net" || c.Port != 2222 || c.InternalIP != "" || c.SSHTarget() != "root@metal.example.net" {
		t.Fatalf("got %+v", c)
	}

	_, err = FromEnv(func(string) string { return "" })
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("empty environment: %v", err)
	}
	for _, v := range []string{EnvHost, EnvKey, EnvHostKey, EnvExternalIP} {
		if !strings.Contains(err.Error(), v) {
			t.Errorf("the error doesn't name %s: %v", v, err)
		}
	}
	if strings.Contains(err.Error(), EnvInternalIP) || strings.Contains(err.Error(), EnvHostname) {
		t.Errorf("an optional variable is asked for: %v", err)
	}

	for name, bad := range map[string]map[string]string{
		"no SHA256 pin":           {EnvHostKey: "ab:cd:ef"},
		"a private external IP":   {EnvExternalIP: "10.0.0.5"},
		"an IPv6 external IP":     {EnvExternalIP: "2001:db8::1"},
		"internal = external":     {EnvInternalIP: "203.0.113.10"},
		"internal not an address": {EnvInternalIP: "lan"},
		"hostname not a name":     {EnvHostname: "metal"},
		"bad port":                {EnvHost: "root@h:99999"},
	} {
		e := map[string]string{}
		for k, v := range env {
			e[k] = v
		}
		for k, v := range bad {
			e[k] = v
		}
		if _, err := FromEnv(func(k string) string { return e[k] }); err == nil || errors.Is(err, ErrNotConfigured) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseTarget(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4":            "root 1.2.3.4 22",
		"ubuntu@1.2.3.4":     "ubuntu 1.2.3.4 22",
		"root@metal.net:222": "root metal.net 222",
		"[2001:db8::1]:22":   "root 2001:db8::1 22",
	} {
		u, a, p, err := ParseTarget(in)
		if got := u + " " + a + " " + strconv.Itoa(p); err != nil || got != want {
			t.Errorf("%s: got %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "@h", "root@", "a b"} {
		if _, _, _, err := ParseTarget(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestWrongHostKeySendsNothing(t *testing.T) {
	m, d := newPair(t, "root")
	d.Config.HostKey = "SHA256:" + strings.Repeat("B", 43)
	_, err := d.Create(ctxT(t), testbed.RunID("abc123"), testbed.Spec{Role: "metal", CPUs: 1, Memory: "1GiB", Disk: "1GiB"})
	if !errors.Is(err, sshboot.ErrHostKey) {
		t.Fatalf("want ErrHostKey, got %v", err)
	}
	cmds, _, auths := m.seen()
	if len(cmds) != 0 || auths != 0 {
		t.Fatalf("the machine saw %d commands and %d key offers from a client that didn't trust it", len(cmds), auths)
	}
}

func TestExecQuotesAndCopyToUsesStdin(t *testing.T) {
	m, d := newPair(t, "root")
	ctx := ctxT(t)
	machine, err := d.Create(ctx, testbed.RunID("abc123"), testbed.Spec{Role: "metal", CPUs: 1, Memory: "1GiB", Disk: "1GiB"})
	if err != nil {
		t.Fatal(err)
	}
	if machine.Name != "kvt-abc123-metal" {
		t.Fatalf("name %q", machine.Name)
	}
	m.setHandler(func(cmd string, _ []byte) (string, int) {
		if strings.HasPrefix(cmd, "'false'") {
			return "nope\n", 3
		}
		return "ok\n", 0
	})
	out, err := d.Exec(ctx, machine, "echo", "it's $HOME", "a;b")
	if err != nil || out != "ok\n" {
		t.Fatalf("exec: %q %v", out, err)
	}
	if _, err := d.Exec(ctx, machine, "false"); err == nil {
		t.Fatal("a failing command returned no error")
	}
	// The connection survives a command's own failure.
	if _, err := d.Exec(ctx, machine, "true"); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(t.TempDir(), "kevasod")
	payload := []byte("\x7fELF binary\x00with $(things) in it")
	if err := os.WriteFile(local, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyTo(ctx, machine, local, "/usr/local/bin/kevasod"); err != nil {
		t.Fatal(err)
	}
	cmds, stdins, _ := m.seen()
	if got := cmds[1]; got != `'echo' 'it'\''s $HOME' 'a;b'` {
		t.Errorf("exec sent %q", got)
	}
	last := cmds[len(cmds)-1]
	if !strings.Contains(last, "chmod 0755") || !strings.Contains(last, "'/usr/local/bin/kevasod'") || strings.Contains(last, "ELF") {
		t.Errorf("copy sent %q", last)
	}
	if string(stdins[len(stdins)-1]) != string(payload) {
		t.Errorf("copy's stdin %q", stdins[len(stdins)-1])
	}
	if ms, _ := d.List(ctx); len(ms) != 0 {
		t.Errorf("list: %v (the driver creates nothing)", ms)
	}
	info, _ := d.SSH(ctx, machine)
	if info.User != "root" || info.KeyFile != d.Config.KeyFile || info.Host != d.Config.Address {
		t.Errorf("ssh info %+v", info)
	}
}

func TestANonRootUserRunsThroughSudo(t *testing.T) {
	m, d := newPair(t, "ubuntu")
	if _, err := d.Run(ctxT(t), "id -u", nil); err != nil {
		t.Fatal(err)
	}
	cmds, _, _ := m.seen()
	if len(cmds) != 1 || cmds[0] != "sudo -n sh -c 'id -u'" {
		t.Fatalf("sent %q", cmds)
	}
}

// machineState is a fake machine's state for the reset: the baseline it recorded, what it has
// now, and whether the reset "works" (the state goes back to the baseline once the plan ran).
type machineState struct {
	mu        sync.Mutex
	baseline  string
	now       State
	after     State // what StateScript shows once the plan's last step ran
	planDone  bool
	leftovers map[string]string // check name → what it prints
	order     []string
}

func (s *machineState) handle(cmd string, stdin []byte) (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case strings.HasPrefix(cmd, "cat "+BaselineFile):
		return s.baseline, 0
	case strings.HasPrefix(cmd, "umask 077 && mkdir -p "+BaselineDir):
		s.baseline = string(stdin)
		return "", 0
	case cmd == StateScript:
		if s.planDone {
			return s.after.Render(), 0
		}
		return s.now.Render(), 0
	}
	for _, st := range Plan(PlanInput{}) {
		if strings.HasPrefix(st.Name, "remove kevaso-* users") && cmd == st.Script {
			s.planDone = true
		}
	}
	for _, c := range Checklist(Ports) {
		if cmd == c.Script {
			s.order = append(s.order, "check:"+c.Name)
			return s.leftovers[c.Name], 0
		}
	}
	s.order = append(s.order, "step")
	return "", 0
}

func TestResetRunsThePlanThenTheChecklist(t *testing.T) {
	m, d := newPair(t, "root")
	ctx := ctxT(t)
	dirty := fresh
	dirty.Packages = append(slices.Clone(fresh.Packages), "docker.io")
	dirty.Tables = append(slices.Clone(fresh.Tables), "inet kevaso")
	dirty.IPForward = "1"
	st := &machineState{baseline: fresh.Render(), now: dirty, after: fresh}
	m.setHandler(st.handle)

	if err := d.Reset(ctx); err != nil {
		t.Fatalf("a reset that worked: %v", err)
	}
	cmds, _, _ := m.seen()
	all := strings.Join(cmds, "\n")
	for _, want := range []string{"apt-get purge -y -qq docker.io", "nft delete table inet kevaso", "ip_forward=0"} {
		if !strings.Contains(all, want) {
			t.Errorf("the reset never ran %q", want)
		}
	}
	if strings.Contains(all, "nft delete table inet provider") {
		t.Error("the reset deleted a table of the baseline")
	}
	// Every step comes before every check.
	firstCheck := slices.IndexFunc(st.order, func(s string) bool { return strings.HasPrefix(s, "check:") })
	if firstCheck < 0 || slices.Contains(st.order[firstCheck:], "step") {
		t.Errorf("steps and checks interleaved: %v", st.order)
	}
	if n := len(st.order) - firstCheck; n != len(Checklist(Ports)) {
		t.Errorf("%d checks ran, want %d", n, len(Checklist(Ports)))
	}
}

func TestResetFailsLoudlyOnLeftovers(t *testing.T) {
	m, d := newPair(t, "root")
	still := fresh
	still.Packages = append(slices.Clone(fresh.Packages), "docker.io")
	st := &machineState{baseline: fresh.Render(), now: still, after: still,
		leftovers: map[string]string{"no Kevaso link is left": "kvbr0\n", "nothing listens on the suite's ports": "0.0.0.0:6443\n"}}
	m.setHandler(st.handle)
	err := d.Reset(ctxT(t))
	if !errors.Is(err, ErrNotClean) {
		t.Fatalf("want ErrNotClean, got %v", err)
	}
	for _, want := range []string{"no Kevaso link is left: kvbr0", "0.0.0.0:6443", "package still installed: docker.io"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error doesn't name %q: %v", want, err)
		}
	}
}

func TestResetNeedsABaseline(t *testing.T) {
	m, d := newPair(t, "root")
	st := &machineState{now: fresh, after: fresh}
	m.setHandler(st.handle)
	if err := d.Reset(ctxT(t)); !errors.Is(err, ErrNoBaseline) {
		t.Fatalf("want ErrNoBaseline, got %v", err)
	}
	if cmds, _, _ := m.seen(); len(cmds) != 1 {
		t.Errorf("without a baseline the reset still sent %d commands", len(cmds)-1)
	}
}

func TestRecordBaselineOnlyOnAFreshMachine(t *testing.T) {
	m, d := newPair(t, "root")
	ctx := ctxT(t)
	st := &machineState{now: fresh, after: fresh, leftovers: map[string]string{"no docker": "/usr/bin/docker\n"}}
	m.setHandler(st.handle)
	if _, err := d.RecordBaseline(ctx); err == nil || !strings.Contains(err.Error(), "isn't fresh") {
		t.Fatalf("a machine with docker got a baseline: %v", err)
	}
	if st.baseline != "" {
		t.Fatal("a baseline was written anyway")
	}
	st.leftovers = nil
	b, err := d.RecordBaseline(ctx)
	if err != nil || st.baseline != fresh.Render() || !slices.Equal(b.Packages, fresh.Packages) {
		t.Fatalf("fresh machine: %v, wrote %q", err, st.baseline)
	}
	// Once there, it's kept: a second call reads it and writes nothing.
	st.now.Packages = append(st.now.Packages, "docker.io")
	if b, err := d.RecordBaseline(ctx); err != nil || slices.Contains(b.Packages, "docker.io") {
		t.Fatalf("second call: %+v %v", b, err)
	}
}
