package cloudhypervisor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/sdk/kri"
)

// fakeHost records commands and keeps files in memory.
type fakeHost struct {
	mu     sync.Mutex
	cmds   []string
	files  map[string][]byte
	answer func(cmd string) (string, error) // scripted outputs
}

func newFakeHost() *fakeHost { return &fakeHost{files: map[string][]byte{}} }

func (h *fakeHost) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	h.cmds = append(h.cmds, cmd)
	if h.answer != nil {
		out, err := h.answer(cmd)
		return []byte(out), err
	}
	if strings.HasPrefix(cmd, "systemctl is-active") {
		return []byte("inactive"), errors.New("exit 3")
	}
	if strings.HasPrefix(cmd, "lvs") {
		return []byte("  kv-x kevaso Vwi-a-tz--"), nil
	}
	return nil, nil
}
func (h *fakeHost) WriteFile(p string, data []byte, _ os.FileMode) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[p] = bytes.Clone(data)
	return nil
}
func (h *fakeHost) ReadFile(p string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(b), nil
}
func (h *fakeHost) RemoveAll(p string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k := range h.files {
		if k == p || strings.HasPrefix(k, p+"/") {
			delete(h.files, k)
		}
	}
	return nil
}
func (h *fakeHost) Glob(pattern string) ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for k := range h.files {
		if ok, _ := path.Match(pattern, k); ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}
func (h *fakeHost) commands() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.cmds...)
}

func newRuntime(t *testing.T, h Host) *Runtime {
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(sk)
	return &Runtime{Host: h, Arch: "aarch64", ExecKey: signer, ExecPub: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), Version: Version}
}

func id(name string) kri.ID { return kri.ID{Namespace: "dev", Name: name, UID: "uid-" + name} }

func spec(name string) kri.Spec {
	return kri.Spec{ID: id(name), Image: "ubuntu-24.04", CPU: 2, Memory: 4 << 30, DiskBytes: 20 << 30}
}

func indexOf(cmds []string, prefix string) int {
	for i, c := range cmds {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

func TestNames(t *testing.T) {
	a, b := NamesFor(id("web")), NamesFor(kri.ID{Namespace: "dev", Name: "web", UID: "other"})
	if len(a.Tap) > 15 {
		t.Fatalf("tap name %q longer than the kernel's 15", a.Tap)
	}
	if a == b {
		t.Fatal("a re-created silo (new UID) reuses the old one's names")
	}
	mac := MAC(id("web"))
	if NamesFor(id("web")) != a || MAC(kri.ID{Namespace: "dev", Name: "web", UID: "uid-web"}) != mac {
		t.Fatal("names aren't stable")
	}
	if !strings.HasPrefix(MAC(id("web")), "52:4b:") {
		t.Fatalf("MAC %s isn't locally administered", MAC(id("web")))
	}
}

func TestAllocateIP(t *testing.T) {
	ip, err := AllocateIP(nil)
	if err != nil || ip.String() != "10.64.0.2" {
		t.Fatalf("first: %v %v", ip, err)
	}
	ip, _ = AllocateIP([]string{"10.64.0.2", "10.64.0.4"})
	if ip.String() != "10.64.0.3" {
		t.Fatalf("gap: %v", ip)
	}
	var all []string
	for i := 2; i < 255; i++ {
		all = append(all, fmt.Sprintf("10.64.0.%d", i))
	}
	if _, err := AllocateIP(all); err == nil {
		t.Fatal("a full /24 still allocated (broadcast?)")
	}
}

func TestRenderedFiles(t *testing.T) {
	ud := UserData("ssh-ed25519 AAAA exec", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", "ssh-ed25519 BBBB host")
	for _, want := range []string{"name: kevaso", "ssh-ed25519 AAAA exec", "ssh_pwauth: false", "lock_passwd: true", "disable_root: true", "      abc", "ed25519_public: ssh-ed25519 BBBB host"} {
		if !strings.Contains(ud, want) {
			t.Errorf("user-data missing %q", want)
		}
	}
	n := NamesFor(id("web"))
	u := Unit(n, 2, 4096, BinDir+"/CLOUDHV_EFI.fd", MAC(id("web")))
	for _, want := range []string{
		"User=kevaso-vmm", "NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "DevicePolicy=closed",
		"DeviceAllow=/dev/kvm rw", "DeviceAllow=/dev/kevaso/" + n.LV + " rw", "InaccessiblePaths=/var/lib/kevaso ",
		"--memory size=4096M", "image_type=raw", "tap=" + n.Tap, "TemporaryFileSystem=" + SilosDir + "\n", "BindPaths=" + n.Dir + "\n", "--vsock cid=3,socket=" + n.Vsock + " ",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q", want)
		}
	}
	nc := NetworkConfig("52:4b:00:00:00:01", AllocateIPMust(t), "web3")
	if !strings.Contains(nc, "nameservers: { addresses: [10.64.0.1], search: [web3.kevaso, kevaso] }") {
		t.Errorf("dns: %s", nc)
	}
	if !strings.Contains(nc, "10.64.0.2/24") || !strings.Contains(nc, "via: 10.64.0.1") {
		t.Errorf("network-config:\n%s", nc)
	}
}

func AllocateIPMust(t *testing.T) netip.Addr {
	a, err := AllocateIP(nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCreateDoesItInOrderAndOnce(t *testing.T) {
	h := newFakeHost()
	r := newRuntime(t, h)
	ctx := context.Background()
	if err := r.Create(ctx, spec("web")); err != nil {
		t.Fatal(err)
	}
	cmds := h.commands()
	order := []string{"install -d", "lvcreate -q -T kevaso/silos -V 20480m", "qemu-img convert -n --target-is-zero -O raw /var/lib/kevaso-images/ubuntu-24.04-aarch64.img",
		"cloud-localds", "rm -f", "chown kevaso-vmm", "ip tuntap add", "ip link set", "systemctl daemon-reload"}
	last := -1
	for _, step := range order {
		i := indexOf(cmds, step)
		if i <= last {
			t.Fatalf("%q missing or out of order in:\n%s", step, strings.Join(cmds, "\n"))
		}
		last = i
	}
	n := NamesFor(id("web"))
	if _, ok := h.files[n.Dir+"/user-data"]; !ok {
		// written then removed: the fake keeps writes, rm is a command; check the rm targets it
		t.Log("user-data written through WriteFile")
	}
	if !strings.Contains(cmds[indexOf(cmds, "rm -f")], n.Dir+"/user-data") {
		t.Fatal("user-data (with the guest's private host key) isn't removed after building the seed")
	}
	if _, ok := h.files["/etc/systemd/system/"+n.Unit]; !ok {
		t.Fatal("unit not written")
	}
	st, ok := r.state(id("web"))
	if !ok || st.IP != "10.64.0.2" || st.HostKey == "" || st.Started {
		t.Fatalf("state %+v", st)
	}
	// A second silo gets the next address; creating the first again does nothing.
	_ = r.Create(ctx, spec("db"))
	if st2, _ := r.state(id("db")); st2.IP != "10.64.0.3" {
		t.Fatalf("second silo IP %s", st2.IP)
	}
	before := len(h.commands())
	_ = r.Create(ctx, spec("web"))
	if len(h.commands()) != before {
		t.Fatal("creating an existing silo ran commands again")
	}
}

func TestCreateFailureCleansUp(t *testing.T) {
	h := newFakeHost()
	h.answer = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "qemu-img") {
			return "no space left", errors.New("exit 1")
		}
		if strings.HasPrefix(cmd, "systemctl is-active") {
			return "inactive", errors.New("exit 3")
		}
		if strings.HasPrefix(cmd, "lvs") {
			return "  kv-x", nil
		}
		return "", nil
	}
	r := newRuntime(t, h)
	err := r.Create(context.Background(), spec("web"))
	if err == nil || !strings.Contains(err.Error(), "no space left") {
		t.Fatalf("create error %v", err)
	}
	if _, ok := r.state(id("web")); ok {
		t.Fatal("a failed create left its state behind")
	}
	if indexOf(h.commands(), "lvremove -q -y kevaso/"+NamesFor(id("web")).LV) < 0 {
		t.Fatal("a failed create left its disk behind")
	}
}

func TestStatusAndDelete(t *testing.T) {
	h := newFakeHost()
	r := newRuntime(t, h)
	ctx := context.Background()
	if s, _ := r.Status(ctx, id("web")); s.State != kri.Absent {
		t.Fatalf("absent: %+v", s)
	}
	_ = r.Create(ctx, spec("web"))
	if s, _ := r.Status(ctx, id("web")); s.State != kri.Created {
		t.Fatalf("created: %+v", s)
	}
	_ = r.Start(ctx, id("web"))
	h.answer = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "systemctl is-active") {
			return "active", nil
		}
		return "", nil
	}
	if s, _ := r.Status(ctx, id("web")); s.State != kri.Running || s.Address != "10.64.0.2" {
		t.Fatalf("running: %+v", s)
	}
	h.answer = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "systemctl is-active") {
			return "inactive", errors.New("exit 3")
		}
		return "", nil
	}
	if s, _ := r.Status(ctx, id("web")); s.State != kri.Stopped {
		t.Fatalf("stopped after a start: %+v", s)
	}
	if err := r.Delete(ctx, id("web")); err != nil {
		t.Fatal(err)
	}
	cmds := h.commands()
	n := NamesFor(id("web"))
	for _, want := range []string{"systemctl stop " + n.Unit, "ip link del " + n.Tap} {
		if indexOf(cmds, want) < 0 {
			t.Errorf("delete didn't run %q", want)
		}
	}
	if s, _ := r.Status(ctx, id("web")); s.State != kri.Absent {
		t.Fatalf("after delete: %+v", s)
	}
	if err := r.Delete(ctx, id("web")); err != nil {
		t.Fatalf("delete is idempotent: %v", err)
	}
	if err := r.Start(ctx, id("web")); !errors.Is(err, kri.ErrNotFound) {
		t.Fatalf("start on absent: %v", err)
	}
}

func TestDigestFromSums(t *testing.T) {
	sums := "abc123 *noble-server-cloudimg-arm64.img\ndef456 *noble-server-cloudimg-amd64.img\n"
	if digestFromSums([]byte(sums), "noble-server-cloudimg-amd64.img") != "def456" {
		t.Fatal("wrong digest")
	}
	if digestFromSums([]byte(sums), "other.img") != "" {
		t.Fatal("found a file that isn't listed")
	}
}

// ── Exec against an in-process SSH server standing in for the guest ─────────

type guest struct {
	addr    string
	hostKey ssh.Signer
	allowed ssh.PublicKey
	mu      sync.Mutex
	ran     []string
}

func startGuest(t *testing.T, allowed ssh.PublicKey) *guest {
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	hk, _ := ssh.NewSignerFromKey(sk)
	g := &guest{hostKey: hk, allowed: allowed}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	g.addr = l.Addr().String()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(m ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if m.User() == GuestUser && bytes.Equal(k.Marshal(), g.allowed.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(hk)
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, _ := nch.Accept()
					go func() {
						defer func() { _ = ch.Close() }()
						for req := range creqs {
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							cmd := string(req.Payload[4:])
							_ = req.Reply(true, nil)
							_, _ = io.ReadAll(ch)
							g.mu.Lock()
							g.ran = append(g.ran, cmd)
							g.mu.Unlock()
							code := 0
							if strings.Contains(cmd, "exit 4") {
								code = 4
							} else {
								_, _ = ch.Write([]byte("hi\n"))
							}
							st := make([]byte, 4)
							binary.BigEndian.PutUint32(st, uint32(code))
							_, _ = ch.SendRequest("exit-status", false, st)
							return
						}
					}()
				}
			}()
		}
	}()
	return g
}

func runningRuntime(t *testing.T, hostKey ssh.PublicKey) (*Runtime, *fakeHost) {
	h := newFakeHost()
	r := newRuntime(t, h)
	_ = r.Create(context.Background(), spec("web"))
	st, _ := r.state(id("web"))
	st.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey)))
	_ = r.saveState(st)
	h.answer = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "systemctl is-active") {
			return "active", nil
		}
		return "", nil
	}
	return r, h
}

func TestExecPinsTheGuestKeyAndRunsWithSudo(t *testing.T) {
	r, _ := runningRuntime(t, ed25519Pub(t)) // placeholder, replaced below
	g := startGuest(t, r.ExecKey.PublicKey())
	r2, _ := runningRuntime(t, g.hostKey.PublicKey())
	r2.ExecKey, r2.ExecPub = r.ExecKey, r.ExecPub
	r2.DialSSH = func(ctx context.Context, _ string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return dialSSH(ctx, g.addr, cfg) // the guest's IP isn't routable in a unit test
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	code, err := r2.Exec(ctx, id("web"), kri.ExecRequest{Command: []string{"echo", "it's"}, Stdout: &out})
	if err != nil || code != 0 || out.String() != "hi\n" {
		t.Fatalf("exec: %d %q %v", code, out.String(), err)
	}
	g.mu.Lock()
	ran := g.ran[0]
	g.mu.Unlock()
	if ran != `sudo -n -- 'echo' 'it'\''s'` {
		t.Fatalf("guest ran %q", ran)
	}
	code, err = r2.Exec(ctx, id("web"), kri.ExecRequest{Command: []string{"sh", "-c", "exit 4"}})
	if err != nil || code != 4 {
		t.Fatalf("exit code: %d %v", code, err)
	}
}

func TestExecRefusesAGuestWithAnotherHostKey(t *testing.T) {
	r, _ := runningRuntime(t, ed25519Pub(t)) // pinned key ≠ the server's
	g := startGuest(t, r.ExecKey.PublicKey())
	r.DialSSH = func(ctx context.Context, _ string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
		return dialSSH(ctx, g.addr, cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := r.Exec(ctx, id("web"), kri.ExecRequest{Command: []string{"true"}}); err == nil {
		t.Fatal("exec succeeded against a guest whose host key isn't the pinned one")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.ran) != 0 {
		t.Fatalf("a command reached the impostor: %v", g.ran)
	}
}

func ed25519Pub(t *testing.T) ssh.PublicKey {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	p, err := ssh.NewPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSetNetworkAndFirewall(t *testing.T) {
	saved, savedGW := Network, Gateway
	defer func() { Network, Gateway = saved, savedGW }()
	SetNetwork(netip.MustParsePrefix("10.64.7.0/24"))
	if Gateway.String() != "10.64.7.1" {
		t.Fatalf("gateway %s", Gateway)
	}
	if ip, _ := AllocateIP(nil); ip.String() != "10.64.7.2" {
		t.Fatalf("first silo %s", ip)
	}
	nft := NFT()
	for _, want := range []string{
		"ip saddr 10.64.7.0/24 ip daddr != { 10.64.0.0/16, 10.62.0.0/16, 10.63.0.0/16 }", // NAT only to the internet
		`iifname "kvbr0" ip daddr { 10.62.0.0/16, 10.63.0.0/16 } drop`,                   // no mesh hosts
		`oifname "kvbr0" drop`,               // nothing reaches a silo unless opened
		`iifname "kvt*" oifname "kvt*" drop`, // no silo-to-silo on the bridge
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("firewall missing %q:\n%s", want, nft)
		}
	}
}
