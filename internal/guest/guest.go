// Package guest is kvo-guest, the helper inside a silo (design §8.2, §10.1). It's a client of the
// host's secret broker over vsock and nothing more: it can't raise what the silo may have, since
// every decision is made on the host and the control plane.
//
//	kvo-guest secret get NAME [--for D] [--wait D]   print a secret's value (grants with deliver: broker)
//	kvo-guest sign KEY [--slot N] [--for D] [--wait D]   sign stdin with a key that never enters the silo; prints hex
//
// When the grant says a use needs a person's yes (approval: required), the command waits, saying
// which approval it waits on, until someone answers or the request expires: --for is the access
// asked for once approved, --wait how long to wait (the cluster's defaults otherwise).
//
//	kvo-guest public-key KEY            the key's public half, hex
//	kvo-guest pane report NAME [--state S] [--progress 0.4] [--title T] [--message M] [--field L=V]… [--ttl 60s]
//	kvo-guest pane html NAME --bundle FILE [--data JSON|-] [--ttl 30s]   report a pane (one way, §10.1)
//	kvo-guest sync [--once]             write file and env deliveries, and keep them up to date
//	kvo-guest ingress [--install]       be an ingress controller (--install: as a service, in a VM)
//
// kevasod copies itself into the silo as /usr/local/bin/kvo-guest; called by that name it runs this.
package guest

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"kevaso.com/core/api/client"
)

// Dialer opens a connection to the broker. The real one is vsock to the host (CID 2); tests use a
// unix socket.
type Dialer func(ctx context.Context) (net.Conn, error)

// DefaultDialer is vsock to the host, or $KVO_GUEST_BROKER (unix:PATH) for testing.
func DefaultDialer(ctx context.Context) (net.Conn, error) {
	if p, ok := strings.CutPrefix(os.Getenv("KVO_GUEST_BROKER"), "unix:"); ok {
		var d net.Dialer
		return d.DialContext(ctx, "unix", p)
	}
	return dialVsock(client.BrokerPort)
}

// Call sends one request and reads one answer.
func Call(ctx context.Context, dial Dialer, req client.BrokerRequest) (client.BrokerResponse, error) {
	c, err := dial(ctx)
	if err != nil {
		return client.BrokerResponse{}, fmt.Errorf("broker: %w", err)
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return client.BrokerResponse{}, err
	}
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	if !sc.Scan() {
		if sc.Err() != nil {
			return client.BrokerResponse{}, sc.Err()
		}
		return client.BrokerResponse{}, errors.New("broker: no answer")
	}
	var resp client.BrokerResponse
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		return resp, err
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// PollEvery is how often a call waiting for a person's yes asks again.
var PollEvery = 2 * time.Second

// Ask sends a request and, while it waits for a person's yes, asks again every interval with the
// pending approval's name (which doesn't replace it), until it's answered or expires. waiting is
// told once which approval it waits on.
func Ask(ctx context.Context, dial Dialer, req client.BrokerRequest, interval time.Duration, waiting func(client.ApprovalWait)) (client.BrokerResponse, error) {
	told := ""
	for {
		resp, err := Call(ctx, dial, req)
		if err != nil || resp.Pending == nil {
			return resp, err
		}
		if resp.Pending.Name != told && waiting != nil {
			waiting(*resp.Pending)
			told = resp.Pending.Name
		}
		req.Approval = resp.Pending.Name
		select {
		case <-ctx.Done():
			return client.BrokerResponse{}, fmt.Errorf("stopped waiting for approval %s: %w", resp.Pending.Name, ctx.Err())
		case <-time.After(interval):
		}
	}
}

// waiting tells the person at the silo what to ask for.
func waiting(w io.Writer) func(client.ApprovalWait) {
	return func(a client.ApprovalWait) {
		_, _ = fmt.Fprintf(w, "kvo-guest: waiting for a person's yes: kvo approve %s -n %s (expires %s)\n",
			a.Name, a.Namespace, a.ExpiresAt.Local().Format(time.Kitchen))
	}
}

// approvalFlags reads --for D and --wait D.
func approvalFlags(req *client.BrokerRequest, args []string) error {
	for len(args) > 0 {
		if len(args) < 2 {
			return fmt.Errorf("%s needs a value", args[0])
		}
		switch args[0] {
		case "--for":
			req.For = args[1]
		case "--wait":
			req.Wait = args[1]
		default:
			return fmt.Errorf("unknown flag %s", args[0])
		}
		if _, err := time.ParseDuration(args[1]); err != nil {
			return fmt.Errorf("%s %q: %v", args[0], args[1], err)
		}
		args = args[2:]
	}
	return nil
}

// Main runs kvo-guest with its arguments (after the program name).
func Main(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	err := run(ctx, DefaultDialer, "/", args, stdin, stdout, stderr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "kvo-guest:", err)
		return 1
	}
	return 0
}

func run(ctx context.Context, dial Dialer, root string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	usage := errors.New("usage: kvo-guest secret get NAME [--for D] [--wait D] | sign KEY [--slot N] [--for D] [--wait D] < payload | public-key KEY | pane report NAME … | pane html NAME --bundle FILE … | port open NAME [--for D] [--wait D] | port close NAME | sync [--once] | ingress [--install]")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "secret":
		if len(args) < 3 || args[1] != "get" {
			return usage
		}
		req := client.BrokerRequest{Op: client.OpGetSecret, Name: args[2]}
		if err := approvalFlags(&req, args[3:]); err != nil {
			return err
		}
		resp, err := Ask(ctx, dial, req, PollEvery, waiting(stderr))
		if err != nil {
			return err
		}
		defer clear(resp.Value)
		_, err = stdout.Write(resp.Value)
		return err
	case "sign":
		if len(args) < 2 {
			return usage
		}
		req := client.BrokerRequest{Op: client.OpSign, Name: args[1]}
		rest := args[2:]
		if len(rest) >= 2 && rest[0] == "--slot" {
			n, err := strconv.ParseInt(rest[1], 10, 64)
			if err != nil {
				return fmt.Errorf("--slot %q: %w", rest[1], err)
			}
			req.Slot, rest = &n, rest[2:]
		}
		if err := approvalFlags(&req, rest); err != nil {
			return err
		}
		payload, err := io.ReadAll(io.LimitReader(stdin, 512<<10))
		if err != nil {
			return err
		}
		req.Payload = payload
		resp, err := Ask(ctx, dial, req, PollEvery, waiting(stderr))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, hex.EncodeToString(resp.Signature))
		return err
	case "pane":
		return paneCommand(ctx, dial, args[1:], stdin, stdout)
	case "port":
		return portCommand(ctx, dial, args[1:], stdout, stderr)
	case "public-key":
		if len(args) != 2 {
			return usage
		}
		resp, err := Call(ctx, dial, client.BrokerRequest{Op: client.OpPublicKey, Name: args[1]})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, resp.PublicKey)
		return err
	case "ingress":
		if len(args) == 2 && args[1] == "--install" {
			return InstallIngress()
		}
		if len(args) != 1 {
			return usage
		}
		return (&Ingress{Dial: dial}).Run(ctx)
	case "sync":
		once := len(args) == 2 && args[1] == "--once"
		if len(args) > 2 || (len(args) == 2 && !once) {
			return usage
		}
		s := &Syncer{Dial: dial, Root: root}
		if once {
			return s.SyncOnce(ctx)
		}
		return s.Run(ctx)
	}
	return usage
}

// ── file and env deliveries ──────────────────────────────────────────────────

// Where the helper keeps env deliveries and what it wrote. /run is tmpfs: nothing reaches the disk.
const (
	EnvFile   = "/run/kevaso/secrets.env"
	stateFile = "/run/kevaso/delivered.json"
	profile   = "/etc/profile.d/kevaso-secrets.sh"
)

// Syncer writes a silo's file and env deliveries and keeps them current.
type Syncer struct {
	Dial Dialer
	Root string // "/" in a silo; a temp dir in tests
	Log  func(string, ...any)
}

func (s *Syncer) path(p string) string { return filepath.Join(s.Root, p) }

func (s *Syncer) log(f string, a ...any) {
	if s.Log != nil {
		s.Log(f, a...)
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "kvo-guest: "+f+"\n", a...)
	}
}

// SyncOnce reads the deliveries and writes them, removing ones that are gone.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	resp, err := Call(ctx, s.Dial, client.BrokerRequest{Op: client.OpDeliveries})
	if err != nil {
		return err
	}
	var written []string
	env := map[string]string{}
	for _, d := range resp.Deliveries {
		switch d.Mode {
		case "file":
			if !strings.HasPrefix(filepath.Clean(d.Path), "/run/") {
				s.log("skipping %s: %s isn't under /run (tmpfs)", d.Name, d.Path)
				continue
			}
			v, err := Call(ctx, s.Dial, client.BrokerRequest{Op: client.OpGetSecret, Name: d.Name})
			if err != nil {
				return fmt.Errorf("%s: %w", d.Name, err)
			}
			err = writeAtomic(s.path(filepath.Clean(d.Path)), v.Value, 0o400)
			clear(v.Value)
			if err != nil {
				return err
			}
			written = append(written, filepath.Clean(d.Path))
		case "env":
			v, err := Call(ctx, s.Dial, client.BrokerRequest{Op: client.OpGetSecret, Name: d.Name})
			if err != nil {
				return fmt.Errorf("%s: %w", d.Name, err)
			}
			env[d.Env] = string(v.Value)
			clear(v.Value)
		}
	}
	if len(env) > 0 {
		if err := writeAtomic(s.path(EnvFile), []byte(envFile(env)), 0o400); err != nil {
			return err
		}
		written = append(written, EnvFile)
		script := "# Kevaso: secrets delivered as environment variables (root only)\n[ -r " + EnvFile + " ] && { set -a; . " + EnvFile + "; set +a; }\n"
		if err := writeAtomic(s.path(profile), []byte(script), 0o644); err != nil {
			return err
		}
	}
	// What we wrote before and isn't delivered any more goes away.
	var before []string
	if b, err := os.ReadFile(s.path(stateFile)); err == nil {
		_ = json.Unmarshal(b, &before)
	}
	for _, p := range before {
		if !contains(written, p) {
			_ = os.Remove(s.path(p))
		}
	}
	if len(env) == 0 {
		_ = os.Remove(s.path(profile))
	}
	b, _ := json.Marshal(written)
	return writeAtomic(s.path(stateFile), b, 0o600)
}

// Run syncs, then again on every change the broker announces (and every five minutes).
func (s *Syncer) Run(ctx context.Context) error {
	for {
		if err := s.SyncOnce(ctx); err != nil {
			s.log("sync: %v", err)
		}
		changed := make(chan struct{}, 1)
		wctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		go s.watch(wctx, changed)
		select {
		case <-ctx.Done():
			cancel()
			return ctx.Err()
		case <-changed:
		case <-wctx.Done():
		}
		cancel()
		select { // a burst of changes: one sync
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// watch signals changed on the first event, or when the connection drops (re-sync, reconnect).
func (s *Syncer) watch(ctx context.Context, changed chan<- struct{}) {
	signal := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	c, err := s.Dial(ctx)
	if err != nil {
		time.Sleep(2 * time.Second)
		signal()
		return
	}
	defer func() { _ = c.Close() }()
	go func() { <-ctx.Done(); _ = c.Close() }()
	if err := json.NewEncoder(c).Encode(client.BrokerRequest{Op: client.OpWatch}); err != nil {
		signal()
		return
	}
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		var ev client.BrokerResponse
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.Event == "changed" {
			signal()
			return
		}
	}
	if ctx.Err() == nil {
		time.Sleep(2 * time.Second)
		signal()
	}
}

func envFile(env map[string]string) string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "='" + strings.ReplaceAll(env[k], "'", `'\''`) + "'\n")
	}
	return b.String()
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".kvo-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
