package kvoadm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/admconfig"
)

// sshd is a tiny SSH server: one host key, key auth for one client key, and every exec answers
// with its name.
type sshd struct {
	addr string
	fp   string
}

func newEd25519(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
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

func startSSHD(t *testing.T, name string, client ssh.PublicKey) *sshd {
	t.Helper()
	hostKey, _ := newEd25519(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), client.Marshal()) {
			return nil, nil
		}
		return nil, net.ErrClosed
	}}
	cfg.AddHostKey(hostKey)
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = nc.Close() }()
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
					go func() {
						defer func() { _ = ch.Close() }()
						for req := range creqs {
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							_ = req.Reply(true, nil)
							_, _ = ch.Write([]byte(name))
							_, _ = ch.SendRequest("exit-status", false, make([]byte, 4))
							return
						}
					}()
				}
			}()
		}
	}()
	return &sshd{addr: l.Addr().String(), fp: ssh.FingerprintSHA256(hostKey.PublicKey())}
}

// clientKeyFile writes an SSH client key kvoadm can log in with.
func clientKeyFile(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	s, k := newEd25519(t)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, s.PublicKey()
}

// closedAddr is an address nothing listens on.
func closedAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	_ = l.Close()
	return a
}

func runOn(t *testing.T, c interface {
	Run(context.Context, string, []byte) ([]byte, error)
}) string {
	t.Helper()
	b, err := c.Run(context.Background(), "hostname", nil)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// From where you are, the first address that answers and is the host is the one used: a LAN
// address that doesn't answer is skipped, and so is one where another machine answers.
func TestDialHostAtTriesTheAddressesInOrder(t *testing.T) {
	key, pub := clientKeyFile(t)
	home := startSSHD(t, "home1", pub)
	impostor := startSSHD(t, "someone-else", pub)
	h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "home1", Annotations: map[string]string{AnnotationSSHHostKey: home.fp}}}
	kc := admconfig.New(t.TempDir(), "c")
	if _, err := kc.AddAddresses("home1", false, "me@"+closedAddr(t), "me@"+impostor.addr, "me@"+home.addr); err != nil {
		t.Fatal(err)
	}
	old := reachTimeout
	reachTimeout = time.Second
	t.Cleanup(func() { reachTimeout = old })
	var out bytes.Buffer
	conn, o, err := dialHostAt(context.Background(), kc, h, InitOptions{SSHKey: key}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if got := runOn(t, conn); got != "home1" {
		t.Fatalf("connected to %q", got)
	}
	if o.User != "me" || net.JoinHostPort(o.Address, strconv.Itoa(o.SSHPort)) != home.addr {
		t.Fatalf("options: %+v", o)
	}
	if !strings.Contains(out.String(), "reached at me@"+home.addr) || !strings.Contains(out.String(), "expected "+home.fp) {
		t.Fatalf("it says which address worked and why the others didn't:\n%s", out.String())
	}

	// None answers as the host: every address and why, and how to add one.
	kc.RemoveAddresses("home1", "me@"+home.addr)
	h.Annotations = map[string]string{AnnotationSSHHostKey: home.fp}
	_, _, err = dialHostAt(context.Background(), kc, h, InitOptions{SSHKey: key}, strings.NewReader(""), &out)
	if err == nil || !strings.Contains(err.Error(), "any of its addresses") || !strings.Contains(err.Error(), "kvoadm host ssh home1 add") {
		t.Fatalf("no address works: %v", err)
	}
}

// The cluster's own record (kevaso.com/ssh) is tried after this laptop's list.
func TestTheClustersRecordComesLast(t *testing.T) {
	kc := admconfig.New(t.TempDir(), "c")
	_, _ = kc.AddAddresses("w", false, "192.168.1.50", "me@w.ts.net:2222")
	h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "w", Annotations: map[string]string{AnnotationSSH: "root@203.0.113.9:22"}}}
	var got []string
	for _, t := range hostTargets(kc, h) {
		got = append(got, t.String())
	}
	if strings.Join(got, " ") != "root@192.168.1.50:22 me@w.ts.net:2222 root@203.0.113.9:22" {
		t.Fatalf("order: %v", got)
	}
	_, _ = kc.AddAddresses("w", true, "root@203.0.113.9") // this machine's list: tried first, and once
	if got := hostTargets(kc, h); len(got) != 3 || got[0].Host != "203.0.113.9" {
		t.Fatalf("an address is tried once, this machine's first: %v", got)
	}
	if got := hostTargets(nil, h); len(got) != 1 {
		t.Fatalf("no cluster folder: the record only: %v", got)
	}
}

// A command given a host's name (reset, backup, kms…) reaches it through the cluster folder's
// list, with the host key the folder pinned, and the folder's SSH key.
func TestDialHostByNameUsesTheClusterFolder(t *testing.T) {
	key, pub := clientKeyFile(t)
	home := startSSHD(t, "home1", pub)
	root := t.TempDir()
	t.Setenv(admconfig.EnvHome, root)
	t.Setenv(admconfig.EnvCluster, "")
	kc := admconfig.New(root, "lab")
	kc.Local.SSHKey = key
	kc.RecordHost("home1", "me@"+home.addr, home.fp)
	_, _ = kc.AddAddresses("home1", true, "me@"+closedAddr(t))
	if err := kc.Save(); err != nil {
		t.Fatal(err)
	}
	o, err := parseTarget([]string{"home1"})
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := dialHost(context.Background(), o, nil, strings.NewReader(""), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if got := runOn(t, conn); got != "home1" {
		t.Fatalf("connected to %q", got)
	}
}

// kvoadm host ssh lists, adds and removes this laptop's addresses for a host.
func TestHostSSHCommand(t *testing.T) {
	root := t.TempDir()
	t.Setenv(admconfig.EnvHome, root)
	t.Setenv(admconfig.EnvCluster, "")
	if err := admconfig.New(root, "lab").Save(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	ctx := context.Background()
	if err := hostSSH(ctx, []string{"w1", "add", "192.168.1.50", "me@w1.ts.net"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := hostSSH(ctx, []string{"w1", "add", "bad addr"}, &out); err == nil {
		t.Fatal("a bad address is refused")
	}
	out.Reset()
	if err := hostSSH(ctx, []string{"w1", "--cluster", "lab"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "root@192.168.1.50:22") || !strings.Contains(out.String(), "me@w1.ts.net:22") || !strings.Contains(out.String(), "team (cluster.yaml)") {
		t.Fatalf("list:\n%s", out.String())
	}
	if err := hostSSH(ctx, []string{"w1", "add", "10.0.0.7", "--local"}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	_ = hostSSH(ctx, []string{"w1"}, &out)
	if !strings.HasPrefix(out.String(), "1.") || !strings.Contains(strings.SplitN(out.String(), "\n", 2)[0], "root@10.0.0.7:22") || !strings.Contains(out.String(), "this machine (local.yaml)") {
		t.Fatalf("this machine's address first:\n%s", out.String())
	}
	if err := hostSSH(ctx, []string{"w1", "remove", "192.168.1.50", "10.0.0.7"}, &out); err != nil {
		t.Fatal(err)
	}
	kc, err := admconfig.Load(root, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if a := kc.Addresses("w1"); len(a) != 1 || a[0] != "me@w1.ts.net" {
		t.Fatalf("after remove: %v", a)
	}
	if err := hostSSH(ctx, []string{"w1", "frobnicate", "x"}, &out); err == nil {
		t.Fatal("an unknown operation is refused")
	}
}

// --cluster is taken off the arguments of the commands given an address, and only theirs.
func TestTakeClusterForAddressCommands(t *testing.T) {
	rest, name, err := takeCluster([]string{"reset", "home1", "--cluster", "lab", "--yes"})
	if err != nil || name != "lab" || strings.Join(rest, " ") != "reset home1 --yes" {
		t.Fatalf("%v %q %v", rest, name, err)
	}
	if _, _, err := takeCluster([]string{"reset", "--cluster"}); err == nil {
		t.Fatal("--cluster with no value")
	}
	for args, want := range map[string]bool{
		"reset h": true, "backup h": true, "kms rotate h": true, "plugin install h": true, "store migrate h": true,
		"host kept h": true, "host trust-control-plane h": true, "host enable-worker h": true,
		"init h": false, "host add h": false, "host list": false, "upgrade": false, "users resign h": false,
	} {
		if got := addressCommand(strings.Fields(args)); got != want {
			t.Fatalf("%s: %v", args, got)
		}
	}
}
