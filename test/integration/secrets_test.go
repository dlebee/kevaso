package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/login"
)

func secretObj(name string, labels map[string]string, value string) *v1.Secret {
	s := &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3", Labels: labels}}
	if value != "" {
		s.Spec.Value = []byte(value)
	}
	return s
}

func grantObj(name string, spec v1.GrantSpec) *v1.Grant {
	return &v1.Grant{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Grant"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3"}, Spec: spec}
}

func status(err error) int {
	var ce *client.Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return 0
}

func (c *cluster) as(t *testing.T, user string) *client.Client {
	t.Helper()
	tok, err := login.Login(c.ctx, c.url, c.ca, login.Options{Open: browser(t, c.invite(t, user))})
	if err != nil {
		t.Fatal(err)
	}
	cl, _ := client.NewTLS(c.url, c.ca, nil, nil)
	cl.Token = func(context.Context) (string, error) { return tok.AccessToken, nil }
	return cl
}

func (c *cluster) bind(t *testing.T, user, kind, role string) {
	t.Helper()
	if err := c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: user, Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: kind, Name: role},
		Subjects: []v1.Subject{{Kind: "User", Name: user}}}); err != nil {
		t.Fatal(err)
	}
}

// Design §8.4–8.6 through the API: values are never in reads, read-value is its own power,
// write-only means nobody, rules by label and by name, and no back door through grants or silos.
func TestSecretsAccess(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	// The design's web3-dev role: everyday secrets by label, one key by name.
	if err := c.admin.Create(c.ctx, &v1.Role{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Role"},
		ObjectMeta: meta.ObjectMeta{Name: "web3-dev", Namespace: "web3"}, Rules: []v1.PolicyRule{
			{Verbs: []string{"list", "use"}, Resources: []string{"secrets"}, Selector: map[string]string{"sensitivity": "normal"}},
			{Verbs: []string{"use"}, Resources: []string{"secrets"}, ResourceNames: []string{"validator-1-key"}},
			{Verbs: []string{"get", "list", "watch", "create", "update", "delete"}, Resources: []string{"grants", "silos"}},
		}}); err != nil {
		t.Fatal(err)
	}
	c.bind(t, "ada", "ClusterRole", "admin")
	c.bind(t, "ed", "ClusterRole", "editor")
	c.bind(t, "dev", "Role", "web3-dev")
	ada, ed, dev := c.as(t, "ada"), c.as(t, "ed"), c.as(t, "dev")

	normal := map[string]string{"sensitivity": "normal"}
	critical := map[string]string{"sensitivity": "critical"}
	infura := secretObj("infura-key", normal, "sk-infura-value-1")
	if err := ada.Create(c.ctx, infura); err != nil {
		t.Fatal(err)
	}
	if infura.Status.Version != 1 || infura.Status.Size != len("sk-infura-value-1") {
		t.Fatalf("create response: status %+v", infura.Status)
	}
	var raw json.RawMessage
	if err := ada.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/infura-key", nil, &raw); err != nil || strings.Contains(string(raw), `"value"`) {
		t.Fatalf("get carries a value: %s %v", raw, err)
	}
	key := secretObj("validator-1-key", critical, "")
	key.Spec.Type, key.Spec.Generate = v1.SecretEd25519, true
	if err := ada.Create(c.ctx, key); err != nil {
		t.Fatal(err)
	}
	if key.Status.PublicKey == "" || key.Status.Version != 1 {
		t.Fatalf("generated key: %+v", key.Status)
	}
	// Re-applying the same object (generate: true) keeps the key: it's made only once.
	_ = ada.Get(c.ctx, "Secret", "web3", "validator-1-key", key)
	pub := key.Status.PublicKey
	if err := ada.Update(c.ctx, key); err != nil || key.Status.PublicKey != pub || key.Status.Version != 1 {
		t.Fatalf("re-apply regenerated the key: %+v %v", key.Status, err)
	}
	dbRoot := secretObj("db-root", critical, "root-password-1")
	if err := ada.Create(c.ctx, dbRoot); err != nil {
		t.Fatal(err)
	}

	// Rotation: a new value is a new version.
	_ = ada.Get(c.ctx, "Secret", "web3", "infura-key", infura)
	infura.Spec.Value = []byte("sk-infura-value-2")
	if err := ada.Update(c.ctx, infura); err != nil || infura.Status.Version != 2 {
		t.Fatalf("rotate: %+v %v", infura.Status, err)
	}

	// No read returns a value: get, list.
	for _, cl := range []*client.Client{ada, ed, c.admin} {
		if err := cl.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets", nil, &raw); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "c2staW5mdXJh") || strings.Contains(string(raw), "sk-infura") || strings.Contains(string(raw), `"value"`) {
			t.Fatalf("a list carries a value: %s", raw)
		}
	}

	// read-value: the admin may, the editor may not; nobody for a write-only key.
	var v client.SecretValue
	if err := ada.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/infura-key/value", nil, &v); err != nil || string(v.Value) != "sk-infura-value-2" || v.Version != 2 {
		t.Fatalf("admin read-value: %q v%d %v", v.Value, v.Version, err)
	}
	if err := ed.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/infura-key/value", nil, &v); status(err) != http.StatusForbidden {
		t.Fatalf("editor read-value: want 403, got %v", err)
	}
	for _, cl := range []*client.Client{ada, c.admin} {
		if err := cl.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/validator-1-key/value", nil, &v); status(err) != http.StatusForbidden || !strings.Contains(err.Error(), "write-only") {
			t.Fatalf("reading a signing key: want 403 write-only, got %v", err)
		}
	}

	// Rules by label: dev sees only the normal secrets.
	l, err := dev.List(c.ctx, "Secret", "web3")
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Items) != 1 || !strings.Contains(string(l.Items[0]), `"infura-key"`) {
		t.Fatalf("dev lists %d secrets: %s", len(l.Items), l.Items)
	}
	if err := dev.Get(c.ctx, "Secret", "web3", "db-root", &v1.Secret{}); status(err) != http.StatusForbidden {
		t.Fatalf("dev reading a critical secret's metadata: want 403, got %v", err)
	}

	// No back door through grants: naming a secret needs use on it, and the secret's own rules win.
	if err := dev.Create(c.ctx, grantObj("rpc", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "infura-key", Deliver: v1.DeliverInject, To: &v1.InjectTarget{Host: "mainnet.infura.io"}}}})); err != nil {
		t.Fatalf("dev granting a normal secret: %v", err)
	}
	if err := dev.Create(c.ctx, grantObj("db", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db-root"}}})); status(err) != http.StatusForbidden {
		t.Fatalf("dev granting a critical secret: want 403, got %v", err)
	}
	if err := dev.Create(c.ctx, grantObj("copy-key", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "validator-1-key", Deliver: v1.DeliverFile}}})); status(err) != http.StatusUnprocessableEntity {
		t.Fatalf("delivering a signing key as a file: want 422, got %v", err)
	}
	if err := dev.Create(c.ctx, grantObj("validator", v1.GrantSpec{Operations: &v1.GrantOperations{Sign: &v1.SignOperation{KeyRef: "validator-1-key", SlashingProtection: true}}})); err != nil {
		t.Fatalf("dev letting a silo sign with the key it may use: %v", err)
	}

	// No back door through silos: giving a silo a grant needs use on the grant's secrets too.
	if err := ada.Create(c.ctx, grantObj("db-root", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db-root", Deliver: v1.DeliverFile}}})); err != nil {
		t.Fatal(err)
	}
	s := silo("thief", "web3")
	s.Spec.Grants = []string{"db-root"}
	if err := dev.Create(c.ctx, s); status(err) != http.StatusForbidden {
		t.Fatalf("dev giving a silo someone else's grant: want 403, got %v", err)
	}
	s = silo("rpc-node", "web3")
	s.Spec.Grants = []string{"rpc"}
	if err := dev.Create(c.ctx, s); err != nil {
		t.Fatalf("dev giving a silo its own grant: %v", err)
	}
	s.Spec.Grants = []string{"rpc", "missing"}
	if err := dev.Update(c.ctx, s); status(err) != http.StatusUnprocessableEntity {
		t.Fatalf("a grant that doesn't exist: want 422, got %v", err)
	}
	if err := ed.Create(c.ctx, func() *v1.Silo { s := silo("db-client", "web3"); s.Spec.Grants = []string{"db-root"}; return s }()); err != nil {
		t.Fatalf("editor (use on every secret) giving a silo the db grant: %v", err)
	}

	// Deleting a secret drops its value: a new one of the same name starts empty.
	if err := ada.Delete(c.ctx, "Secret", "web3", "db-root"); err != nil {
		t.Fatal(err)
	}
	if err := ada.Create(c.ctx, secretObj("db-root", critical, "")); err != nil {
		t.Fatal(err)
	}
	if err := ada.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/db-root/value", nil, &v); status(err) != http.StatusNotFound {
		t.Fatalf("re-created secret: want 404 no value, got %v (%q)", err, v.Value)
	}

	// Every value read is in the audit log, allowed or not.
	reads := 0
	for _, e := range c.audit.Entries() {
		if e.Verb == "read-value" {
			reads++
		}
	}
	if reads < 5 {
		t.Fatalf("%d read-value entries in the audit log", reads)
	}
}

// The recovery key is made once, through the admin socket only; rotating the master key keeps every
// value readable.
func TestRecoveryKeyAndRotation(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	if err := c.admin.Create(c.ctx, secretObj("a", nil, "value-a")); err != nil {
		t.Fatal(err)
	}
	var rk client.RecoveryKey
	if err := c.admin.Call(c.ctx, http.MethodPost, "/admin/kms/recovery-key", nil, &rk); err != nil || !strings.HasPrefix(rk.RecoveryKey, "KVR1-") {
		t.Fatalf("recovery key: %q %v", rk.RecoveryKey, err)
	}
	if err := c.admin.Call(c.ctx, http.MethodPost, "/admin/kms/recovery-key", nil, &rk); status(err) != http.StatusConflict {
		t.Fatalf("second recovery key: want 409, got %v", err)
	}
	c.bind(t, "ada", "ClusterRole", "admin")
	if err := c.as(t, "ada").Call(c.ctx, http.MethodPost, "/admin/kms/rotate", nil, nil); status(err) != http.StatusForbidden {
		t.Fatalf("rotate over the network: want 403, got %v", err)
	}
	var rot client.KMSRotation
	if err := c.admin.Call(c.ctx, http.MethodPost, "/admin/kms/rotate", nil, &rot); err != nil || rot.Rewrapped != 1 {
		t.Fatalf("rotate: %+v %v", rot, err)
	}
	var v client.SecretValue
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/a/value", nil, &v); err != nil || string(v.Value) != "value-a" {
		t.Fatalf("after rotation: %q %v", v.Value, err)
	}
}
