package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

func clusterSecret(name string, plugins, hosts []string, value string) *v1.ClusterSecret {
	cs := &v1.ClusterSecret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterSecret"},
		ObjectMeta: meta.ObjectMeta{Name: name},
		Spec:       v1.ClusterSecretSpec{Plugins: plugins, Hosts: hosts}}
	if value != "" {
		cs.Spec.Value = []byte(value)
	}
	return cs
}

func (c *cluster) asUser(t *testing.T, name string) (*client.Client, func()) {
	t.Helper()
	return c.srv.InProcessAs(pki.Identity{Type: "user", Name: name})
}

func (c *cluster) asHost(t *testing.T, name, role string) (*client.Client, func()) {
	t.Helper()
	return c.srv.InProcessAs(pki.Identity{Type: "host", Name: name, Role: role})
}

// workerCert is a host certificate enrolled the way kevasod worker does.
func (c *cluster) workerCert(t *testing.T, name string) *client.Client {
	t.Helper()
	var tok client.JoinTokenResponse
	if err := c.admin.Call(c.ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: name, Roles: []string{"worker"}}, &tok); err != nil {
		t.Fatal(err)
	}
	anon, err := client.NewTLS(c.url, c.ca, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := anon.Enroll(c.ctx, tok.Token, name, "worker")
	if err != nil {
		t.Fatal(err)
	}
	w, err := client.NewTLS(c.url, c.ca, cred.Certificate, cred.Key)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func wantCode(t *testing.T, err error, code int, what string) {
	t.Helper()
	if status(err) != code {
		t.Fatalf("%s: want %d, got %v", what, code, err)
	}
}

// ClusterSecret is cluster-admin only for every verb, including a namespace admin and a
// ClusterRole that names the resource; status is the server's; the value is write-only except
// --reveal for a cluster-admin and the host value route.
func TestClusterSecret(t *testing.T) {
	c := newCluster(t)
	if err := c.admin.Create(c.ctx, ns("web3")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "ada", Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "admin"},
		Subjects: []v1.Subject{{Kind: "User", Name: "ada"}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRole"},
		ObjectMeta: meta.ObjectMeta{Name: "cs-all"}, Rules: []v1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"clustersecrets"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "bob-cs"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "cs-all"},
		Subjects: []v1.Subject{{Kind: "User", Name: "bob"}}}); err != nil {
		t.Fatal(err)
	}
	ada, doneAda := c.asUser(t, "ada")
	defer doneAda()
	bob, doneBob := c.asUser(t, "bob")
	defer doneBob()
	if err := ada.Create(c.ctx, secretObj("ada-key", nil, "x")); err != nil {
		t.Fatalf("namespace admin creating a namespaced secret: %v", err)
	}

	cred, err := c.admin.IssueUserCert(c.ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	root, err := client.NewTLS(c.url, c.ca, cred.Certificate, cred.Key)
	if err != nil {
		t.Fatal(err)
	}

	// Plugins are required. A caller's status is not stored.
	past := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	noPlug := clusterSecret("no-plugin", nil, nil, "x")
	if err := c.admin.Create(c.ctx, noPlug); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "plugins") {
		t.Fatalf("no plugins: want 422 mentioning plugins, got %v", err)
	}
	badName := clusterSecret("bad-plugin", []string{"JuiceFS"}, nil, "x")
	if err := c.admin.Create(c.ctx, badName); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "plugins") {
		t.Fatalf("plugin name: want 422, got %v", err)
	}
	if err := c.admin.Create(c.ctx, clusterSecret("no-value", []string{"juicefs"}, nil, "")); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "needs a value") {
		t.Fatalf("no value: want 422 needs a value, got %v", err)
	}

	cs := clusterSecret("bucket", []string{"juicefs", "s3"}, nil, "s3cret-bytes")
	cs.Spec.Description = "bucket key"
	cs.Status.Version = 99
	cs.Status.ChangedAt = &past
	if err := root.Create(c.ctx, cs); err != nil {
		t.Fatal(err)
	}
	if cs.Status.Version != 1 || cs.Status.ChangedAt == nil || cs.Status.ChangedAt.Year() == 1999 {
		t.Fatalf("create kept the caller's status: %+v", cs.Status)
	}

	// Every verb: cluster-admin yes, namespace admin and a ClusterRole that names the resource no.
	var got v1.ClusterSecret
	if err := c.admin.Get(c.ctx, "ClusterSecret", "", "bucket", &got); err != nil || got.Spec.Description != "bucket key" || got.Status.Version != 1 {
		t.Fatalf("admin get: %+v %v", got, err)
	}
	if l, err := c.admin.List(c.ctx, "ClusterSecret", ""); err != nil || len(l.Items) != 1 {
		t.Fatalf("admin list: %v %v", l, err)
	}
	for _, who := range []struct {
		name string
		cl   *client.Client
	}{{"namespace admin", ada}, {"clusterrole naming clustersecrets", bob}} {
		if err := who.cl.Create(c.ctx, clusterSecret("other", []string{"juicefs"}, nil, "nope")); status(err) != http.StatusForbidden {
			t.Fatalf("%s create: want 403, got %v", who.name, err)
		}
		if err := who.cl.Get(c.ctx, "ClusterSecret", "", "bucket", &v1.ClusterSecret{}); status(err) != http.StatusForbidden {
			t.Fatalf("%s get: want 403, got %v", who.name, err)
		}
		if _, err := who.cl.List(c.ctx, "ClusterSecret", ""); status(err) != http.StatusForbidden {
			t.Fatalf("%s list: want 403, got %v", who.name, err)
		}
		stale := got
		stale.Spec.Description = "changed"
		stale.Spec.Value = []byte("nope")
		if err := who.cl.Update(c.ctx, &stale); status(err) != http.StatusForbidden {
			t.Fatalf("%s update: want 403, got %v", who.name, err)
		}
		if err := who.cl.Delete(c.ctx, "ClusterSecret", "", "bucket"); status(err) != http.StatusForbidden {
			t.Fatalf("%s delete: want 403, got %v", who.name, err)
		}
		var v client.SecretValue
		if err := who.cl.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value", nil, &v); status(err) != http.StatusForbidden {
			t.Fatalf("%s reveal: want 403, got %v", who.name, err)
		}
	}

	// A worker and a system node (control-plane certificate) can't get, list or write the object.
	hv1 := c.workerCert(t, "hv1")
	hv2, done2 := c.asHost(t, "hv2", "worker")
	defer done2()
	cp, doneCP := c.asHost(t, "cp1", "control-plane")
	defer doneCP()
	comp, doneComp := c.srv.InProcess()
	defer doneComp()
	for _, who := range []struct {
		name string
		cl   *client.Client
	}{{"worker", hv1}, {"system node", cp}, {"kevasod", comp}} {
		if err := who.cl.Get(c.ctx, "ClusterSecret", "", "bucket", &v1.ClusterSecret{}); status(err) != http.StatusForbidden {
			t.Fatalf("%s get: want 403, got %v", who.name, err)
		}
		if _, err := who.cl.List(c.ctx, "ClusterSecret", ""); status(err) != http.StatusForbidden {
			t.Fatalf("%s list: want 403, got %v", who.name, err)
		}
		if err := who.cl.Create(c.ctx, clusterSecret("from-"+who.name, []string{"juicefs"}, nil, "nope")); status(err) != http.StatusForbidden {
			t.Fatalf("%s create: want 403, got %v", who.name, err)
		}
	}

	// Status on update is the server's, on a value change and without one. /status is refused.
	if err := c.admin.Get(c.ctx, "ClusterSecret", "", "bucket", &got); err != nil {
		t.Fatal(err)
	}
	got.Spec.Description = "renamed"
	got.Status.Version = 99
	got.Status.ChangedAt = &past
	if err := c.admin.Update(c.ctx, &got); err != nil || got.Status.Version != 1 || got.Status.ChangedAt.Year() == 1999 || got.Spec.Description != "renamed" {
		t.Fatalf("update without a value kept the caller's status: %+v %v", got.Status, err)
	}
	if err := c.admin.Get(c.ctx, "ClusterSecret", "", "bucket", &got); err != nil {
		t.Fatal(err)
	}
	got.Spec.Value = []byte("s3cret-bytes-2")
	got.Status.Version = 99
	got.Status.ChangedAt = &past
	if err := c.admin.Update(c.ctx, &got); err != nil || got.Status.Version != 2 || got.Status.ChangedAt.Year() == 1999 {
		t.Fatalf("rotate: %+v %v", got.Status, err)
	}
	forged := got
	forged.Status.Version = 99
	if err := c.admin.UpdateStatus(c.ctx, &forged); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "status is set by the server") {
		t.Fatalf("/status: want 422, got %v", err)
	}
	if err := c.admin.Get(c.ctx, "ClusterSecret", "", "bucket", &got); err != nil || got.Status.Version != 2 {
		t.Fatalf("status write landed: %+v %v", got.Status, err)
	}

	// The value is never on get or list, and there is no list of values. Reveal is one value.
	var raw json.RawMessage
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket", nil, &raw); err != nil || strings.Contains(string(raw), "s3cret") || strings.Contains(string(raw), `"value"`) {
		t.Fatalf("get carries a value: %s %v", raw, err)
	}
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets", nil, &raw); err != nil || strings.Contains(string(raw), "s3cret") || strings.Contains(string(raw), `"value"`) {
		t.Fatalf("list carries a value: %s %v", raw, err)
	}
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/value", nil, &raw); status(err) != http.StatusNotFound {
		t.Fatalf("a list of values: want 404, got %v %s", err, raw)
	}
	if err := root.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value", nil, &raw); err != nil {
		t.Fatal(err)
	}
	body := strings.TrimSpace(string(raw))
	if strings.HasPrefix(body, "[") {
		t.Fatalf("reveal answered a list: %s", body)
	}
	var v client.SecretValue
	if err := json.Unmarshal(raw, &v); err != nil || string(v.Value) != "s3cret-bytes-2" || v.Version != 2 {
		t.Fatalf("cluster-admin reveal: %q v%d %v (%s)", v.Value, v.Version, err, body)
	}

	// Hosts empty, plugins set: a worker certificate and a system node both read the value.
	for _, who := range []struct {
		name string
		cl   *client.Client
	}{{"worker", hv1}, {"other worker", hv2}, {"system node", cp}} {
		if err := who.cl.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value", nil, &v); err != nil || string(v.Value) != "s3cret-bytes-2" {
			t.Fatalf("%s value, hosts empty: %q %v", who.name, v.Value, err)
		}
	}

	// hosts names hv1 only: hv1 yes, everyone else who is a host no.
	only := clusterSecret("only-hv1", []string{"juicefs"}, []string{"hv1"}, "only-hv1-bytes")
	if err := c.admin.Create(c.ctx, only); err != nil {
		t.Fatal(err)
	}
	if err := hv1.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/only-hv1/value", nil, &v); err != nil || string(v.Value) != "only-hv1-bytes" {
		t.Fatalf("named worker: %q %v", v.Value, err)
	}
	for _, who := range []struct {
		name string
		cl   *client.Client
	}{{"other worker", hv2}, {"system node", cp}, {"namespace admin", ada}} {
		if err := who.cl.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/only-hv1/value", nil, &v); status(err) != http.StatusForbidden {
			t.Fatalf("%s reading a secret that doesn't name them: want 403, got %v", who.name, err)
		}
	}

	// plugins empty: the value route refuses the named host. Stored past admission, so the check
	// is the route's and not only the schema's.
	bare := &v1.ClusterSecret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterSecret"},
		ObjectMeta: meta.ObjectMeta{Name: "bare", UID: "bare-uid"},
		Spec:       v1.ClusterSecretSpec{Hosts: []string{"hv1"}}}
	b, _ := json.Marshal(bare)
	if _, err := c.store.Create(c.ctx, store.Key{Kind: "ClusterSecret", Name: "bare"}, b); err != nil {
		t.Fatal(err)
	}
	if _, err := c.srv.Vault().PutCluster(c.ctx, bare, []byte("bare-value")); err != nil {
		t.Fatal(err)
	}
	if err := hv1.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bare/value", nil, &v); status(err) != http.StatusForbidden {
		t.Fatalf("empty plugins: want 403, got %v %q", err, v.Value)
	}

	if err := c.admin.Delete(c.ctx, "ClusterSecret", "", "bucket"); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Get(c.ctx, "ClusterSecret", "", "bucket", &got); status(err) != http.StatusNotFound {
		t.Fatalf("deleted secret still there: %v", err)
	}
}

// Grants' secrets and container.pull.secretRef resolve a Secret in the namespace. A ClusterSecret
// of the same name is not that secret.
func TestClusterSecretIsNotANamespacedSecret(t *testing.T) {
	c := newCluster(t)
	if err := c.admin.Create(c.ctx, ns("web3")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterSecret("regcred", []string{"juicefs"}, nil, "cluster-token")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterSecret("signer", []string{"juicefs"}, nil, "cluster-key")); err != nil {
		t.Fatal(err)
	}
	puller := containerSilo("puller", "web3", "docker")
	puller.Spec.Container.Image = "ghcr.io/acme/api:v1"
	puller.Spec.Container.Pull = &v1.ImagePull{SecretRef: "regcred"}
	if err := c.admin.Create(c.ctx, puller); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), `no secret "regcred" in namespace web3`) {
		t.Fatalf("pull resolved a ClusterSecret: want no namespaced secret, got %v", err)
	}
	opaque := secretObj("regcred", nil, "namespaced-token")
	if err := c.admin.Create(c.ctx, opaque); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, puller); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "not registry") {
		t.Fatalf("pull used something other than the namespaced secret: %v", err)
	}

	key := secretObj("signer", nil, "")
	key.Spec.Type, key.Spec.Generate = v1.SecretEd25519, true
	if err := c.admin.Create(c.ctx, key); err != nil {
		t.Fatal(err)
	}
	g := grantObj("use-signer", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "signer", Deliver: v1.DeliverFile, Path: "/run/secrets/signer"}}})
	if err := c.admin.Create(c.ctx, g); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "doesn't allow delivery file") {
		t.Fatalf("grant resolved something other than the namespaced signing key: %v", err)
	}
}
