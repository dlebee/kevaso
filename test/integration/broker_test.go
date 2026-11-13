package integration

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
)

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

	eps := c.endpoints(t, "hv1")
	for _, s := range []*v1.Silo{node, other, locked, elsewhere} { // hv1 serves them all, even the one on hv2
		eps.add(t, s)
	}
	get := func(s *v1.Silo, path string) epAnswer { return eps.call(t, s, http.MethodGet, path, nil) }

	// The node gets its broker secret; the same name from another silo is "no secret", like a
	// name that doesn't exist, word for word.
	if a := get(node, "/v1/secrets/db-password"); a.code != 200 || a.body != "pw-1" || a.header.Get("Kevaso-Version") != "1" {
		t.Fatalf("node get db-password: %d %q", a.code, a.body)
	}
	aOther, aMissing := get(other, "/v1/secrets/db-password"), get(node, "/v1/secrets/does-not-exist")
	if aOther.code != 404 || aMissing.code != 404 || strings.ReplaceAll(aOther.msg(), "db-password", "X") != strings.ReplaceAll(aMissing.msg(), "does-not-exist", "X") {
		t.Fatalf("not granted vs missing must look the same: %d %q / %d %q", aOther.code, aOther.msg(), aMissing.code, aMissing.msg())
	}
	// Injected secrets never go to the silo, nor do signing keys, nor (now that the host writes
	// them) file and env secrets.
	for _, name := range []string{"infura-key", "validator-1-key", "tls-key", "legacy-token"} {
		if a := get(node, "/v1/secrets/"+name); a.code != 404 {
			t.Fatalf("%s reached the silo through its endpoint: %d %q", name, a.code, a.body)
		}
	}
	// The host's own ops aren't routes a silo has.
	for _, path := range []string{"/v1/injections", "/v1/deliveries", "/v1/delivery-values", "/v1/panes"} {
		if a := get(node, path); a.code != 404 {
			t.Fatalf("silo reached %s: %d", path, a.code)
		}
	}
	// Assurance: a grant needing a confidential VM gives nothing to a host-assured silo.
	if a := get(locked, "/v1/secrets/db-password"); a.code != 404 {
		t.Fatalf("confidential-only grant served a host-assured silo: %d", a.code)
	}
	// A host only gets secrets for silos placed on it.
	if a := get(elsewhere, "/v1/secrets/db-password"); a.code != 404 || !strings.Contains(a.msg(), "no access") {
		t.Fatalf("hv1 fetching for a silo on hv2: %d %q", a.code, a.body)
	}

	// Sign: verifiable with the public key; slashing protection; no slot, no signature.
	pk := get(node, "/v1/keys/validator-1-key")
	if pk.code != 200 {
		t.Fatalf("public key: %d %s", pk.code, pk.body)
	}
	pub, _ := hex.DecodeString(strings.TrimSpace(pk.body))
	sig := eps.call(t, node, http.MethodPost, "/v1/sign/validator-1-key?slot=7", []byte("block 7"))
	sigBytes, _ := hex.DecodeString(strings.TrimSpace(sig.body))
	if sig.code != 200 || !ed25519.Verify(pub, []byte("block 7"), sigBytes) {
		t.Fatalf("sign: %d %s", sig.code, sig.body)
	}
	if a := eps.call(t, node, http.MethodPost, "/v1/sign/validator-1-key?slot=7", []byte("block 7, other")); a.code != 409 || !strings.Contains(a.msg(), "slashing") {
		t.Fatalf("equivocation: %d %s", a.code, a.body)
	}
	if a := eps.call(t, other, http.MethodPost, "/v1/sign/validator-1-key?slot=7", []byte("x")); a.code != 404 {
		t.Fatalf("a silo without the grant signed: %d", a.code)
	}

	// File and env secrets: the host asks for them for its own silo (with their values), never a silo.
	hv1 := c.host(t, "hv1")
	var dv client.BrokerResponse
	if err := hv1.Call(c.ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{Namespace: "web3", Name: "node", UID: node.UID,
		Request: client.BrokerRequest{Op: client.OpDeliveryValues}}, &dv); err != nil || dv.Error != "" {
		t.Fatalf("delivery values: %v %s", err, dv.Error)
	}
	if len(dv.Deliveries) != 2 || string(dv.Deliveries[0].Value) != "-----BEGIN KEY-----" || dv.Deliveries[0].Path != "/run/secrets/tls.pem" ||
		string(dv.Deliveries[1].Value) != "tok'en" || dv.Deliveries[1].Env != "LEGACY_TOKEN" {
		t.Fatalf("delivery values: %+v", dv.Deliveries)
	}
	var dv2 client.BrokerResponse
	if err := hv1.Call(c.ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{Namespace: "web3", Name: "elsewhere", UID: elsewhere.UID,
		Request: client.BrokerRequest{Op: client.OpDeliveryValues}}, &dv2); err != nil || dv2.Error == "" || len(dv2.Deliveries) != 0 {
		t.Fatalf("hv1 got another host's silo's file secrets: %+v %v", dv2, err)
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
	if allowed < 4 || denied < 9 {
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
