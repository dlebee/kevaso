package integration

import (
	"net/http"
	"net/url"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

// The broker's and the ingress configuration's endpoints are for hosts, and for a host only about
// the silos placed on it (T-04). The check that matters most is the one on who is asking: a person
// whose name is a host's name must not pass for that host, and the local admin is not a host.
// Each caller below gets the endpoint's answer, and only the right host gets a secret.
func TestOnlyTheHostASiloIsPlacedOnGetsItsSecretsOrIngressConfig(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	if err := c.admin.Create(c.ctx, secretObj("db-password", nil, "pw-1")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, grantObj("app", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db-password"}}})); err != nil {
		t.Fatal(err)
	}
	s := silo("node", "web3")
	s.Spec.Grants = []string{"app"}
	if err := c.admin.Create(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv1"
	if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	hv1, hv2, nameSake := c.host(t, "hv1"), c.host(t, "hv2"), c.as(t, "hv1") // a person called hv1

	ask := func(cl *client.Client, uid string) (client.BrokerResponse, int) {
		var resp client.BrokerResponse
		err := cl.Call(c.ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{Namespace: "web3", Name: "node", UID: uid,
			Request: client.BrokerRequest{Op: client.OpGetSecret, Name: "db-password"}}, &resp)
		return resp, status(err)
	}
	if resp, code := ask(hv1, s.UID); code != 0 || string(resp.Value) != "pw-1" {
		t.Fatalf("the host the silo is on gets its secret: code %d, %+v (the control for the rest)", code, resp)
	}
	for name, cl := range map[string]*client.Client{"a person named like the host": nameSake, "the local admin": c.admin} {
		if resp, code := ask(cl, s.UID); code != http.StatusForbidden || len(resp.Value) != 0 {
			t.Errorf("%s asked the broker: code %d, value %q", name, code, resp.Value)
		}
	}
	if resp, code := ask(hv2, s.UID); len(resp.Value) != 0 || resp.Error == "" {
		t.Errorf("another host asked for a silo placed on hv1: code %d, %+v", code, resp)
	}
	if resp, _ := ask(hv1, "not-its-uid"); len(resp.Value) != 0 || resp.Error == "" {
		t.Errorf("the right host, the wrong uid (another silo of that name): %+v", resp)
	}

	q := "?" + url.Values{"namespace": {"web3"}, "name": {"node"}}.Encode()
	ingress := func(cl *client.Client) int {
		return status(cl.Call(c.ctx, http.MethodGet, client.PathAgentIngress+q, nil, nil))
	}
	for name, cl := range map[string]*client.Client{"a person named like the host": nameSake, "the local admin": c.admin, "another host": hv2} {
		if code := ingress(cl); code != http.StatusForbidden {
			t.Errorf("%s asked for the ingress configuration of a silo on hv1: code %d, want 403", name, code)
		}
	}
	if code := ingress(hv1); code == http.StatusForbidden || code == http.StatusUnauthorized {
		t.Errorf("the host the silo is on is refused its ingress configuration: %d", code)
	}
}

// A silo being deleted gets nothing from the broker: its secrets are not handed to a host for a
// silo that is going away.
func TestASiloBeingDeletedGetsNothingFromTheBroker(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	if err := c.admin.Create(c.ctx, secretObj("db-password", nil, "pw-1")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, grantObj("app", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db-password"}}})); err != nil {
		t.Fatal(err)
	}
	s := silo("node", "web3")
	s.Finalizers = []string{"test/hold"} // so a delete marks it instead of removing it
	s.Spec.Grants = []string{"app"}
	if err := c.admin.Create(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv1"
	if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	hv1 := c.host(t, "hv1")
	ask := func() client.BrokerResponse {
		var resp client.BrokerResponse
		_ = hv1.Call(c.ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{Namespace: "web3", Name: "node", UID: s.UID,
			Request: client.BrokerRequest{Op: client.OpGetSecret, Name: "db-password"}}, &resp)
		return resp
	}
	if string(ask().Value) != "pw-1" {
		t.Fatal("the control: a silo that is not being deleted gets its secret")
	}
	if err := c.admin.Delete(c.ctx, "Silo", "web3", "node"); err != nil {
		t.Fatal(err)
	}
	var cur v1.Silo
	if err := c.admin.Get(c.ctx, "Silo", "web3", "node", &cur); err != nil || cur.DeletionTimestamp == nil {
		t.Fatalf("a delete of a silo with a finalizer did not mark it: %v %+v", err, cur.DeletionTimestamp)
	}
	if resp := ask(); len(resp.Value) != 0 {
		t.Fatalf("a silo being deleted was given its secret: %+v", resp)
	}
}

// A secret says how it may be delivered (allowedDelivery). A grant written before the secret was
// restricted must not still hand it out the way it no longer allows: the broker checks the secret
// on every request.
func TestTheBrokerHonoursWhatTheSecretAllowsNow(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	sec := secretObj("db-password", nil, "pw-1")
	if err := c.admin.Create(c.ctx, sec); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, grantObj("app", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db-password"}}})); err != nil {
		t.Fatal(err)
	}
	s := silo("node", "web3")
	s.Spec.Grants = []string{"app"}
	if err := c.admin.Create(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv1"
	if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	hv1 := c.host(t, "hv1")
	ask := func() client.BrokerResponse {
		var resp client.BrokerResponse
		_ = hv1.Call(c.ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{Namespace: "web3", Name: "node", UID: s.UID,
			Request: client.BrokerRequest{Op: client.OpGetSecret, Name: "db-password"}}, &resp)
		return resp
	}
	if string(ask().Value) != "pw-1" {
		t.Fatal("the control: the secret allows every delivery and the broker gives it")
	}
	var cur v1.Secret
	if err := c.admin.Get(c.ctx, "Secret", "web3", "db-password", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Value = nil
	cur.Spec.AllowedDelivery = []string{v1.DeliverFile}
	if err := c.admin.Update(c.ctx, &cur); err != nil {
		t.Skipf("the API refuses to restrict a secret a grant uses that way (%v): the broker's check is behind it", err)
	}
	if resp := ask(); len(resp.Value) != 0 {
		t.Fatalf("the broker handed out a secret in a way it no longer allows: %+v", resp)
	}
}

// A secret's type cannot be changed once it exists: an opaque secret that becomes a signing key
// (or the other way round) would change how every grant of it is honoured.
func TestASecretsTypeCannotChange(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	if err := c.admin.Create(c.ctx, secretObj("db-password", nil, "pw-1")); err != nil {
		t.Fatal(err)
	}
	var cur v1.Secret
	if err := c.admin.Get(c.ctx, "Secret", "web3", "db-password", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Value, cur.Spec.Type, cur.Spec.Generate = nil, v1.SecretEd25519, true
	if err := c.admin.Update(c.ctx, &cur); status(err) != http.StatusUnprocessableEntity {
		t.Fatalf("changing a secret's type: %v, want 422", err)
	}
}

// Opening a silo to the outside needs create on services/expose-public, which an editor lacks,
// also when the silo already exists: the only exemption is a write that leaves the exposure as it
// was, so an editor can change anything else but not turn an unexposed silo into an exposed one.
func TestAnEditorCannotExposeAnExistingSiloPublicly(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	s := silo("web", "web3")
	if err := c.admin.Create(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	c.bind(t, "eddie", "ClusterRole", "editor")
	ed := c.as(t, "eddie")
	var cur v1.Silo
	if err := ed.Get(c.ctx, "Silo", "web3", "web", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Resources.Memory = "2Gi"
	if err := ed.Update(c.ctx, &cur); err != nil {
		t.Fatalf("the control: an editor changes something else about the silo: %v", err)
	}
	if err := ed.Get(c.ctx, "Silo", "web3", "web", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Ports = []v1.SiloPort{{Name: "web", Port: 8080}}
	cur.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Port: "web", HostPort: []string{v1.NetworkExternal}}}}
	if err := ed.Update(c.ctx, &cur); status(err) != http.StatusForbidden {
		t.Fatalf("an editor opened an existing silo to the outside: %v, want 403", err)
	}
}
