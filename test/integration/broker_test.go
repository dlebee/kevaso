package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/guest"
	"kevaso.com/core/sdk/kri"
)

// channels stands in for a runtime's per-silo vsock: one unix socket per silo.
type channels struct{ dir string }

func (c channels) BrokerListen(id kri.ID, _ uint32) (net.Listener, error) {
	return net.Listen("unix", filepath.Join(c.dir, id.UID+".sock"))
}

func (c channels) dialer(uid string) guest.Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", filepath.Join(c.dir, uid+".sock"))
	}
}

func (c *cluster) host(t *testing.T, name string) *client.Client {
	t.Helper()
	var jt client.JoinTokenResponse
	if err := c.admin.Call(c.ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: name, Roles: []string{"worker"}}, &jt); err != nil {
		t.Fatal(err)
	}
	anon, _ := client.NewTLS(c.url, c.ca, nil, nil)
	cred, err := anon.Enroll(c.ctx, jt.Token, name, "worker")
	if err != nil {
		t.Fatal(err)
	}
	hc, err := client.NewTLS(c.url, c.ca, cred.Certificate, cred.Key)
	if err != nil {
		t.Fatal(err)
	}
	return hc
}

// The broker end to end in one process (design §8.2, E014/E015 on the real thing come in e2e): a
// silo gets exactly what its grants give, the way they give it; another silo gets nothing; a host
// gets nothing for silos placed elsewhere; signing keys never come out; every call is audited.
func TestBroker(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	put := func(s *v1.Secret) *v1.Secret {
		t.Helper()
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	put(secretObj("db-password", nil, "pw-1"))
	put(secretObj("tls-key", nil, "-----BEGIN KEY-----"))
	put(secretObj("legacy-token", nil, "tok'en"))
	put(secretObj("infura-key", nil, "sk-inject"))
	key := secretObj("validator-1-key", nil, "")
	key.Spec.Type, key.Spec.Generate = v1.SecretEd25519, true
	put(key)
	for _, g := range []*v1.Grant{
		grantObj("app", v1.GrantSpec{Secrets: []v1.GrantSecret{
			{Name: "db-password"},
			{Name: "tls-key", Deliver: v1.DeliverFile, Path: "/run/secrets/tls.pem"},
			{Name: "legacy-token", Deliver: v1.DeliverEnv},
			{Name: "infura-key", Deliver: v1.DeliverInject, To: &v1.InjectTarget{Host: "mainnet.infura.io"}},
		}}),
		grantObj("validator", v1.GrantSpec{Operations: &v1.GrantOperations{Sign: &v1.SignOperation{KeyRef: "validator-1-key", SlashingProtection: true}}}),
		grantObj("confidential-only", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db-password"}}, Requires: &v1.GrantRequires{Assurance: v1.AssuranceConfidential}}),
	} {
		if err := c.admin.Create(c.ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	place := func(name, host string, grants ...string) *v1.Silo {
		t.Helper()
		s := silo(name, "web3")
		s.Spec.Grants = grants
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host = host
		if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	node := place("node", "hv1", "app", "validator")
	other := place("other", "hv1")
	locked := place("locked", "hv1", "confidential-only")
	elsewhere := place("elsewhere", "hv2", "app")

	dir, _ := os.MkdirTemp("/tmp", "kvb") // unix socket paths are short on macOS
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ch := channels{dir}
	hv1 := &agent.Broker{Client: c.host(t, "hv1")}
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	for _, s := range []*v1.Silo{node, other, locked, elsewhere} { // hv1 serves them all, even the one on hv2
		if err := hv1.Ensure(ctx, ch, kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID}); err != nil {
			t.Fatal(err)
		}
	}
	call := func(s *v1.Silo, req client.BrokerRequest) (client.BrokerResponse, error) {
		return guest.Call(ctx, ch.dialer(s.UID), req)
	}

	// The node gets its broker secret; the same name from another silo is "no secret", like a
	// name that doesn't exist.
	r, err := call(node, client.BrokerRequest{Op: client.OpGetSecret, Name: "db-password"})
	if err != nil || string(r.Value) != "pw-1" || r.Version != 1 {
		t.Fatalf("node get db-password: %q %v", r.Value, err)
	}
	_, errOther := call(other, client.BrokerRequest{Op: client.OpGetSecret, Name: "db-password"})
	_, errMissing := call(node, client.BrokerRequest{Op: client.OpGetSecret, Name: "does-not-exist"})
	if errOther == nil || errMissing == nil || strings.ReplaceAll(errOther.Error(), "db-password", "X") != strings.ReplaceAll(errMissing.Error(), "does-not-exist", "X") {
		t.Fatalf("not granted vs missing must look the same: %v / %v", errOther, errMissing)
	}
	// Injected secrets never go to the silo, nor do signing keys.
	if _, err := call(node, client.BrokerRequest{Op: client.OpGetSecret, Name: "infura-key"}); err == nil {
		t.Fatal("an inject-only secret reached the silo")
	}
	if _, err := call(node, client.BrokerRequest{Op: client.OpGetSecret, Name: "validator-1-key"}); err == nil {
		t.Fatal("a signing key reached the silo")
	}
	// The gate's op isn't something a silo can ask for.
	if _, err := call(node, client.BrokerRequest{Op: client.OpInjections}); err == nil || !strings.Contains(err.Error(), "unknown op") {
		t.Fatalf("silo asking for injections: %v", err)
	}
	// Assurance: a grant needing a confidential VM gives nothing to a host-assured silo.
	if _, err := call(locked, client.BrokerRequest{Op: client.OpGetSecret, Name: "db-password"}); err == nil {
		t.Fatal("confidential-only grant served a host-assured silo")
	}
	// A host only gets secrets for silos placed on it.
	if _, err := call(elsewhere, client.BrokerRequest{Op: client.OpGetSecret, Name: "db-password"}); err == nil || !strings.Contains(err.Error(), "no access") {
		t.Fatalf("hv1 fetching for a silo on hv2: %v", err)
	}

	// Sign: verifiable with the public key; slashing protection; no slot, no signature.
	pk, err := call(node, client.BrokerRequest{Op: client.OpPublicKey, Name: "validator-1-key"})
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(pk.PublicKey)
	slot := int64(7)
	sig, err := call(node, client.BrokerRequest{Op: client.OpSign, Name: "validator-1-key", Payload: []byte("block 7"), Slot: &slot})
	if err != nil || !ed25519.Verify(pub, []byte("block 7"), sig.Signature) {
		t.Fatalf("sign: %v", err)
	}
	if _, err := call(node, client.BrokerRequest{Op: client.OpSign, Name: "validator-1-key", Payload: []byte("block 7, other"), Slot: &slot}); err == nil || !strings.Contains(err.Error(), "slashing") {
		t.Fatalf("equivocation: %v", err)
	}
	if _, err := call(other, client.BrokerRequest{Op: client.OpSign, Name: "validator-1-key", Payload: []byte("x"), Slot: &slot}); err == nil {
		t.Fatal("a silo without the grant signed")
	}

	// File and env deliveries through the helper, into a fake root.
	root := t.TempDir()
	sy := &guest.Syncer{Dial: ch.dialer(node.UID), Root: root, Log: t.Logf}
	if err := sy.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "run/secrets/tls.pem"))
	if err != nil || string(b) != "-----BEGIN KEY-----" {
		t.Fatalf("file delivery: %q %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(root, "run/secrets/tls.pem")); fi.Mode().Perm() != 0o400 {
		t.Fatalf("delivered file mode %v", fi.Mode().Perm())
	}
	env, _ := os.ReadFile(filepath.Join(root, guest.EnvFile))
	if string(env) != "LEGACY_TOKEN='tok'\\''en'\n" {
		t.Fatalf("env delivery: %q", env)
	}

	// Rotation: watchers hear about it; the next sync writes the new value; a delivery that's
	// gone is removed.
	wc, err := ch.dialer(node.UID)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wc.Close() }()
	_, _ = wc.Write([]byte(`{"op":"watch"}` + "\n"))
	buf := make([]byte, 4096)
	_ = wc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := wc.Read(buf); err != nil || !strings.Contains(string(buf[:n]), "ready") {
		t.Fatalf("watch: %q %v", buf[:n], err)
	}
	var tls v1.Secret
	_ = c.admin.Get(c.ctx, "Secret", "web3", "tls-key", &tls)
	tls.Spec.Value = []byte("-----BEGIN KEY v2-----")
	if err := c.admin.Update(c.ctx, &tls); err != nil {
		t.Fatal(err)
	}
	hv1.Notify("web3", "node", "tls-key") // the agent's informers do this on the real host
	if n, err := wc.Read(buf); err != nil || !strings.Contains(string(buf[:n]), `"changed"`) {
		t.Fatalf("watch after rotation: %q %v", buf[:n], err)
	}
	var g v1.Grant
	_ = c.admin.Get(c.ctx, "Grant", "web3", "app", &g)
	g.Spec.Secrets = g.Spec.Secrets[:2] // drop legacy-token's env delivery
	if err := c.admin.Update(c.ctx, &g); err != nil {
		t.Fatal(err)
	}
	if err := sy.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "run/secrets/tls.pem")); string(b) != "-----BEGIN KEY v2-----" {
		t.Fatalf("after rotation: %q", b)
	}
	if _, err := os.Stat(filepath.Join(root, guest.EnvFile)); !os.IsNotExist(err) {
		t.Fatal("env file kept after the delivery went")
	}

	// Every broker call is in the audit log, as the silo, allowed or not.
	var allowed, denied int
	for _, e := range c.audit.Entries() {
		if e.Event == "broker" {
			if !strings.HasPrefix(e.User, "system:silo:web3:") || !strings.Contains(e.Reason, "via host hv1") {
				t.Errorf("audit entry %+v", e)
			}
			if e.Allowed {
				allowed++
			} else {
				denied++
			}
		}
	}
	if allowed < 5 || denied < 6 {
		t.Fatalf("audit: %d allowed, %d denied broker calls", allowed, denied)
	}
}

func TestAffected(t *testing.T) {
	mk := func(ns, name string, grants ...string) *v1.Silo {
		s := silo(name, ns)
		s.Spec.Grants = grants
		return s
	}
	silos := []*v1.Silo{mk("web3", "a", "rpc"), mk("web3", "b", "rpc", "db"), mk("web3", "c"), mk("other", "d", "rpc")}
	grants := []*v1.Grant{grantObj("rpc", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "infura-key"}}}), grantObj("db", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db"}}})}
	names := func(ss []*v1.Silo) string {
		var out []string
		for _, s := range ss {
			out = append(out, s.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(agent.Affected(silos, grants, "Secret", "web3", "infura-key")); got != "a,b" {
		t.Errorf("rotating infura-key reaches %q, want a,b (not d: another namespace's grant of the same name)", got)
	}
	if got := names(agent.Affected(silos, grants, "Grant", "web3", "db")); got != "b" {
		t.Errorf("changing grant db reaches %q", got)
	}
	if got := names(agent.Affected(silos, grants, "Secret", "web3", "nothing")); got != "" {
		t.Errorf("an unused secret reaches %q", got)
	}
}
