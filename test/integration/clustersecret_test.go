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
	"kevaso.com/core/internal/operators"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/rbac"
)

func clusterSecret(name, value string) *v1.ClusterSecret {
	cs := &v1.ClusterSecret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterSecret"},
		ObjectMeta: meta.ObjectMeta{Name: name}}
	if value != "" {
		cs.Spec.Value = []byte(value)
	}
	return cs
}

func (c *cluster) asUser(t *testing.T, name string) (*client.Client, func()) {
	t.Helper()
	return c.srv.InProcessAs(pki.Identity{Type: "user", Name: name})
}

func (c *cluster) asServiceAccount(t *testing.T, namespace, name string) (*client.Client, func()) {
	t.Helper()
	return c.srv.InProcessAs(pki.Identity{Type: "serviceaccount", Name: rbac.ServiceAccountUser(namespace, name)})
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

func clusterRole(name string, rules ...v1.PolicyRule) *v1.ClusterRole {
	return &v1.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRole"},
		ObjectMeta: meta.ObjectMeta{Name: name}, Rules: rules}
}

func clusterBind(name, role string, subs ...v1.Subject) *v1.ClusterRoleBinding {
	return &v1.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: name}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: role}, Subjects: subs}
}

func saSubject(namespace, name string) v1.Subject {
	return v1.Subject{Kind: "ServiceAccount", Name: name, Namespace: namespace}
}

func installedPlugin(name, serviceAccount string) *v1.Plugin {
	return &v1.Plugin{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Plugin"},
		ObjectMeta: meta.ObjectMeta{Name: name},
		Spec: v1.PluginSpec{Version: "1", Controller: &v1.PluginController{
			Host: "10.0.0.8", ServiceAccount: serviceAccount}}}
}

func (c *cluster) readClusterValue(t *testing.T, cl *client.Client, name, query string) (client.SecretValue, error) {
	t.Helper()
	var v client.SecretValue
	path := "/apis/kevaso/v1/clustersecrets/" + name + "/value"
	if query != "" {
		path += "?" + query
	}
	err := cl.Call(c.ctx, http.MethodGet, path, nil, &v)
	return v, err
}

// Manage (create, update, delete, reveal) stays a cluster-admin's when a ClusterRole grants
// those verbs. The same role's get and list are allowed, and the body never carries the value:
// dropping either half makes this fail.
func TestClusterSecretManageIsClusterAdminOnly(t *testing.T) {
	c := newCluster(t)
	if err := c.admin.Create(c.ctx, ns("web3")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "ada", Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "admin"},
		Subjects: []v1.Subject{{Kind: "User", Name: "ada"}}}); err != nil {
		t.Fatal(err)
	}
	// "*" would allow create through ordinary evaluation. It must not, here.
	if err := c.admin.Create(c.ctx, clusterRole("cs-all", v1.PolicyRule{Verbs: []string{"*"}, Resources: []string{"clustersecrets"}})); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterBind("bob-cs", "cs-all", v1.Subject{Kind: "User", Name: "bob"})); err != nil {
		t.Fatal(err)
	}
	ada, doneAda := c.asUser(t, "ada")
	defer doneAda()
	bob, doneBob := c.asUser(t, "bob")
	defer doneBob()

	cred, err := c.admin.IssueUserCert(c.ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	root, err := client.NewTLS(c.url, c.ca, cred.Certificate, cred.Key)
	if err != nil {
		t.Fatal(err)
	}

	cs := clusterSecret("bucket", "s3cret-bytes")
	cs.Spec.Description = "bucket key"
	if err := root.Create(c.ctx, cs); err != nil {
		t.Fatal(err)
	}

	var got v1.ClusterSecret
	if err := bob.Get(c.ctx, "ClusterSecret", "", "bucket", &got); err != nil || got.Spec.Description != "bucket key" || got.Status.Version != 1 {
		t.Fatalf("a ClusterRole's get: %+v %v", got, err)
	}
	if l, err := bob.List(c.ctx, "ClusterSecret", ""); err != nil || len(l.Items) != 1 {
		t.Fatalf("a ClusterRole's list: %v %v", l, err)
	}
	var raw json.RawMessage
	if err := bob.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket", nil, &raw); err != nil || strings.Contains(string(raw), "s3cret") {
		t.Fatalf("get carries a value: %s %v", raw, err)
	}
	if err := bob.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets", nil, &raw); err != nil || strings.Contains(string(raw), "s3cret") {
		t.Fatalf("list carries a value: %s %v", raw, err)
	}

	if err := bob.Create(c.ctx, clusterSecret("other", "nope")); status(err) != http.StatusForbidden {
		t.Fatalf("create with a ClusterRole granting it: want 403, got %v", err)
	}
	stale := got
	stale.Spec.Description = "changed"
	stale.Spec.Value = []byte("nope")
	if err := bob.Update(c.ctx, &stale); status(err) != http.StatusForbidden {
		t.Fatalf("update: want 403, got %v", err)
	}
	if err := bob.Delete(c.ctx, "ClusterSecret", "", "bucket"); status(err) != http.StatusForbidden {
		t.Fatalf("delete: want 403, got %v", err)
	}
	if _, err := c.readClusterValue(t, bob, "bucket", ""); status(err) != http.StatusForbidden {
		t.Fatalf("reveal through a role on clustersecrets: want 403, got %v", err)
	}

	for _, who := range []struct {
		name string
		cl   *client.Client
	}{{"namespace admin", ada}} {
		if err := who.cl.Create(c.ctx, clusterSecret("from-"+who.name, "nope")); status(err) != http.StatusForbidden {
			t.Fatalf("%s create: want 403, got %v", who.name, err)
		}
		if err := who.cl.Get(c.ctx, "ClusterSecret", "", "bucket", &v1.ClusterSecret{}); status(err) != http.StatusForbidden {
			t.Fatalf("%s get: want 403, got %v", who.name, err)
		}
		if _, err := c.readClusterValue(t, who.cl, "bucket", ""); status(err) != http.StatusForbidden {
			t.Fatalf("%s reveal: want 403, got %v", who.name, err)
		}
	}

	v, err := c.readClusterValue(t, root, "bucket", "")
	if err != nil || string(v.Value) != "s3cret-bytes" || v.Version != 1 {
		t.Fatalf("cluster-admin reveal: %q v%d %v", v.Value, v.Version, err)
	}
}

// A pinned ClusterRole bound to a service account reads exactly the names it lists.
func TestClusterSecretPinnedRoleReadsItsNames(t *testing.T) {
	c := newCluster(t)
	for _, name := range []string{"bucket", "metering", "other"} {
		if err := c.admin.Create(c.ctx, clusterSecret(name, name+"-bytes")); err != nil {
			t.Fatal(err)
		}
	}
	sa := operators.ServiceAccountName("juicefs")
	if err := c.admin.Create(c.ctx, clusterRole("juicefs-secrets", v1.PolicyRule{
		Verbs: []string{"get"}, Resources: []string{"clustersecrets/value"}, ResourceNames: []string{"bucket", "metering"},
	})); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterBind("juicefs-secrets", "juicefs-secrets", saSubject(v1.PluginNamespace, sa))); err != nil {
		t.Fatal(err)
	}
	juice, done := c.asServiceAccount(t, v1.PluginNamespace, sa)
	defer done()

	for _, name := range []string{"bucket", "metering"} {
		v, err := c.readClusterValue(t, juice, name, "")
		if err != nil || string(v.Value) != name+"-bytes" || v.Version != 1 {
			t.Fatalf("pinned %s: %q v%d %v", name, v.Value, v.Version, err)
		}
	}
	if _, err := c.readClusterValue(t, juice, "other", ""); status(err) != http.StatusForbidden {
		t.Fatalf("a name the role doesn't list: want 403, got %v", err)
	}
	// The value rule is not get on the object.
	if err := juice.Get(c.ctx, "ClusterSecret", "", "bucket", &v1.ClusterSecret{}); status(err) != http.StatusForbidden {
		t.Fatalf("value rule granted get of the object: %v", err)
	}
}

// An unpinned rule (no resourceNames) grants no value. The same binding can still get the object,
// so a broken binding can't masquerade as the pin.
func TestClusterSecretUnpinnedRuleReadsNone(t *testing.T) {
	c := newCluster(t)
	if err := c.admin.Create(c.ctx, clusterSecret("bucket", "s3cret-bytes")); err != nil {
		t.Fatal(err)
	}
	sa := operators.ServiceAccountName("open")
	if err := c.admin.Create(c.ctx, clusterRole("open-values",
		v1.PolicyRule{Verbs: []string{"get", "list"}, Resources: []string{"clustersecrets"}},
		v1.PolicyRule{Verbs: []string{"get"}, Resources: []string{"clustersecrets/value"}},
	)); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterBind("open-values", "open-values", saSubject(v1.PluginNamespace, sa))); err != nil {
		t.Fatal(err)
	}
	open, done := c.asServiceAccount(t, v1.PluginNamespace, sa)
	defer done()
	if err := open.Get(c.ctx, "ClusterSecret", "", "bucket", &v1.ClusterSecret{}); err != nil {
		t.Fatalf("the binding no longer grants get: %v", err)
	}
	if _, err := c.readClusterValue(t, open, "bucket", ""); status(err) != http.StatusForbidden {
		t.Fatalf("unpinned clustersecrets/value: want 403, got %v", err)
	}

	// "*" with no names matches the resource and still grants no value.
	star := operators.ServiceAccountName("star")
	if err := c.admin.Create(c.ctx, clusterRole("star-get", v1.PolicyRule{Verbs: []string{"get"}, Resources: []string{"*"}})); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterBind("star-get", "star-get", saSubject(v1.PluginNamespace, star))); err != nil {
		t.Fatal(err)
	}
	wide, doneWide := c.asServiceAccount(t, v1.PluginNamespace, star)
	defer doneWide()
	if err := wide.Get(c.ctx, "ClusterSecret", "", "bucket", &v1.ClusterSecret{}); err != nil {
		t.Fatalf("get * no longer matches clustersecrets: %v", err)
	}
	if _, err := c.readClusterValue(t, wide, "bucket", ""); status(err) != http.StatusForbidden {
		t.Fatalf("unpinned *: want 403, got %v", err)
	}
}

// A namespaced Role that names clustersecrets or clustersecrets/value is refused, and the message
// says to use a ClusterRole. A ClusterRole with the same rule is accepted.
func TestClusterSecretRoleNamingItIsRefused(t *testing.T) {
	c := newCluster(t)
	if err := c.admin.Create(c.ctx, ns("web3")); err != nil {
		t.Fatal(err)
	}
	role := func(name string, resources ...string) *v1.Role {
		return &v1.Role{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Role"},
			ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3"},
			Rules:      []v1.PolicyRule{{Verbs: []string{"get"}, Resources: resources}}}
	}
	for _, tc := range []struct {
		name      string
		resources []string
	}{
		{"bad-objects", []string{"clustersecrets"}},
		{"bad-value", []string{"clustersecrets/value"}},
		{"bad-mixed", []string{"secrets", "clustersecrets"}},
	} {
		err := c.admin.Create(c.ctx, role(tc.name, tc.resources...))
		if status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "ClusterRole") {
			t.Fatalf("Role %s resources %v: want 422 pointing at a ClusterRole, got %v", tc.name, tc.resources, err)
		}
	}
	if err := c.admin.Create(c.ctx, role("secrets-only", "secrets")); err != nil {
		t.Fatalf("a Role naming secrets: %v", err)
	}
	if err := c.admin.Create(c.ctx, clusterRole("cs-ok", v1.PolicyRule{Verbs: []string{"get"}, Resources: []string{"clustersecrets", "clustersecrets/value"}, ResourceNames: []string{"bucket"}})); err != nil {
		t.Fatalf("a ClusterRole naming clustersecrets: %v", err)
	}
}

// ?for=PLUGIN&side=node|controller is allowed only for a host certificate. side=node is
// service account plugin-PLUGIN-node; side=controller is plugin-PLUGIN. A worker certificate
// may ask only for the node side. A control-plane certificate may ask for either. A Plugin
// object is not consulted, and the account object itself need not exist. The host may get,
// list and watch the object, and that body never carries a value.
func TestClusterSecretHostForPlugin(t *testing.T) {
	c := newCluster(t)
	for _, name := range []string{"bucket", "metering", "other", "nodesec"} {
		if err := c.admin.Create(c.ctx, clusterSecret(name, name+"-bytes")); err != nil {
			t.Fatal(err)
		}
	}
	juiceSA := operators.ServiceAccountName("juicefs")
	nodeSA := operators.ServiceAccountNodeName("juicefs")
	if err := c.admin.Create(c.ctx, clusterRole("juicefs-secrets", v1.PolicyRule{
		Verbs: []string{"get"}, Resources: []string{"clustersecrets/value"}, ResourceNames: []string{"bucket", "metering"},
	})); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterBind("juicefs-secrets", "juicefs-secrets",
		saSubject(v1.PluginNamespace, juiceSA),
		v1.Subject{Kind: "User", Name: "hv1"}, // a host must not be allowed as this user
	)); err != nil {
		t.Fatal(err)
	}
	// A Plugin that names some other account must not change whose read ?for= uses.
	if err := c.admin.Create(c.ctx, installedPlugin("juicefs", "not-this-account")); err != nil {
		t.Fatal(err)
	}

	hv1 := c.workerCert(t, "hv1")
	cp, doneCP := c.asHost(t, "cp1", "control-plane")
	defer doneCP()
	ada, doneAda := c.asUser(t, "ada")
	defer doneAda()

	for _, who := range []struct {
		name string
		cl   *client.Client
	}{{"worker", hv1}, {"system node", cp}} {
		if _, err := c.readClusterValue(t, who.cl, "bucket", ""); status(err) != http.StatusForbidden {
			t.Fatalf("%s without ?for and side: want 403, got %v", who.name, err)
		}
		if _, err := c.readClusterValue(t, who.cl, "bucket", "for=juicefs"); status(err) != http.StatusForbidden {
			t.Fatalf("%s without side: want 403, got %v", who.name, err)
		}
		if _, err := c.readClusterValue(t, who.cl, "bucket", "for=s3&side=node"); status(err) != http.StatusForbidden {
			t.Fatalf("%s ?for=s3: want 403, got %v", who.name, err)
		}
		if _, err := c.readClusterValue(t, who.cl, "bucket", "for=missing&side=node"); status(err) != http.StatusForbidden {
			t.Fatalf("%s ?for=missing: want 403, got %v", who.name, err)
		}
		if _, err := c.readClusterValue(t, who.cl, "bucket", "for=idle&side=controller"); status(err) != http.StatusForbidden {
			t.Fatalf("%s ?for=idle: want 403, got %v", who.name, err)
		}
		for _, bad := range []string{"for=JuiceFS&side=node", "for=a_b&side=node", "for=a-&side=node", "for=../x&side=node", "for=plugin.juicefs&side=node"} {
			if _, err := c.readClusterValue(t, who.cl, "bucket", bad); status(err) != http.StatusForbidden {
				t.Fatalf("%s %s: want 403, got %v", who.name, bad, err)
			}
		}
		var got v1.ClusterSecret
		if err := who.cl.Get(c.ctx, "ClusterSecret", "", "bucket", &got); err != nil || len(got.Spec.Value) != 0 || got.Status.Version == 0 {
			t.Fatalf("%s get of the object: %+v %v", who.name, got, err)
		}
		var raw json.RawMessage
		if err := who.cl.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket", nil, &raw); err != nil || strings.Contains(string(raw), "bucket-bytes") || strings.Contains(string(raw), `"value"`) {
			t.Fatalf("%s get carries a value: %s %v", who.name, raw, err)
		}
		if err := who.cl.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets", nil, &raw); err != nil || strings.Contains(string(raw), "bucket-bytes") || strings.Contains(string(raw), "metering-bytes") || strings.Contains(string(raw), `"value"`) {
			t.Fatalf("%s list carries a value: %s %v", who.name, raw, err)
		}
		if err := who.cl.Create(c.ctx, clusterSecret("from-"+who.name, "nope")); status(err) != http.StatusForbidden {
			t.Fatalf("%s create: want 403, got %v", who.name, err)
		}
	}
	// A worker certificate asks only for the node side, even when the controller account may read.
	if _, err := c.readClusterValue(t, hv1, "bucket", "for=juicefs&side=controller"); status(err) != http.StatusForbidden || !strings.Contains(err.Error(), "only for a plugin's node side") {
		t.Fatalf("worker side=controller: want 403 naming the side, got %v", err)
	}
	if _, err := c.readClusterValue(t, hv1, "bucket", "for=juicefs&side=node"); status(err) != http.StatusForbidden || !strings.Contains(err.Error(), "node side") {
		t.Fatalf("worker side=node before the node account is bound: want 403, got %v", err)
	}
	for _, name := range []string{"bucket", "metering"} {
		v, err := c.readClusterValue(t, cp, name, "for=juicefs&side=controller")
		if err != nil || string(v.Value) != name+"-bytes" {
			t.Fatalf("system node side=controller %s: %q %v", name, v.Value, err)
		}
	}
	if _, err := c.readClusterValue(t, cp, "other", "for=juicefs&side=controller"); status(err) != http.StatusForbidden {
		t.Fatalf("system node other: want 403, got %v", err)
	}
	if _, err := c.readClusterValue(t, cp, "bucket", "for=juicefs&side=node"); status(err) != http.StatusForbidden {
		t.Fatalf("system node side=node before the node account is bound: want 403, got %v", err)
	}

	if err := c.admin.Create(c.ctx, clusterRole("juicefs-node-secrets", v1.PolicyRule{
		Verbs: []string{"get"}, Resources: []string{"clustersecrets/value"}, ResourceNames: []string{"bucket", "metering", "nodesec"},
	})); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterBind("juicefs-node-secrets", "juicefs-node-secrets", saSubject(v1.PluginNamespace, nodeSA))); err != nil {
		t.Fatal(err)
	}
	for _, who := range []struct {
		name string
		cl   *client.Client
	}{{"worker", hv1}, {"system node", cp}} {
		for _, name := range []string{"bucket", "metering"} {
			v, err := c.readClusterValue(t, who.cl, name, "for=juicefs&side=node")
			if err != nil || string(v.Value) != name+"-bytes" {
				t.Fatalf("%s side=node %s: %q %v", who.name, name, v.Value, err)
			}
		}
	}
	// nodesec is bound only to the node account. A worker reads it on the node side.
	// The controller account cannot, so a lookup that forgot the -node suffix is refused.
	v, err := c.readClusterValue(t, hv1, "nodesec", "for=juicefs&side=node")
	if err != nil || string(v.Value) != "nodesec-bytes" {
		t.Fatalf("worker side=node nodesec: %q %v", v.Value, err)
	}
	if _, err := c.readClusterValue(t, hv1, "bucket", "for=juicefs&side=controller"); status(err) != http.StatusForbidden || !strings.Contains(err.Error(), "only for a plugin's node side") {
		t.Fatalf("worker side=controller after the node binding: want 403 naming the side, got %v", err)
	}
	if _, err := c.readClusterValue(t, cp, "nodesec", "for=juicefs&side=controller"); status(err) != http.StatusForbidden {
		t.Fatalf("system node side=controller nodesec: want 403, got %v", err)
	}

	ch, err := hv1.Watch(c.ctx, "ClusterSecret", "", "0")
	if err != nil {
		t.Fatalf("worker watch: %v", err)
	}
	deadline := time.After(5 * time.Second)
	saw := false
	for !saw {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("worker watch ended before the object")
			}
			if strings.Contains(string(ev.Object), "bucket-bytes") || strings.Contains(string(ev.Object), `"value"`) {
				t.Fatalf("watch carries a value: %s", ev.Object)
			}
			if strings.Contains(string(ev.Object), `"bucket"`) {
				saw = true
			}
		case <-deadline:
			t.Fatal("worker watch showed no clustersecret")
		}
	}
	if _, err := c.readClusterValue(t, ada, "bucket", "for=juicefs"); status(err) != http.StatusForbidden {
		t.Fatalf("a user with ?for=: want 403, got %v", err)
	}
	comp, doneComp := c.srv.InProcess()
	defer doneComp()
	if _, err := c.readClusterValue(t, comp, "bucket", "for=juicefs"); status(err) != http.StatusForbidden {
		t.Fatalf("kevasod with ?for=: want 403, got %v", err)
	}
}

// Status is the server's on create and on update, with or without a new value. /status is refused.
func TestClusterSecretStatusIsServerSet(t *testing.T) {
	c := newCluster(t)
	past := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := c.admin.Create(c.ctx, clusterSecret("no-value", "")); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "needs a value") {
		t.Fatalf("no value: want 422 needs a value, got %v", err)
	}

	cs := clusterSecret("bucket", "s3cret-bytes")
	cs.Spec.Description = "bucket key"
	cs.Status.Version = 99
	cs.Status.ChangedAt = &past
	if err := c.admin.Create(c.ctx, cs); err != nil {
		t.Fatal(err)
	}
	if cs.Status.Version != 1 || cs.Status.ChangedAt == nil || cs.Status.ChangedAt.Year() == 1999 {
		t.Fatalf("create kept the caller's status: %+v", cs.Status)
	}

	var got v1.ClusterSecret
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
	v, err := c.readClusterValue(t, c.admin, "bucket", "")
	if err != nil || string(v.Value) != "s3cret-bytes-2" || v.Version != 2 {
		t.Fatalf("reveal: %q v%d %v", v.Value, v.Version, err)
	}
}

// Grants' secrets and container.pull.secretRef resolve a Secret in the namespace. A ClusterSecret
// of the same name is not that secret.
func TestClusterSecretIsNotANamespacedSecret(t *testing.T) {
	c := newCluster(t)
	if err := c.admin.Create(c.ctx, ns("web3")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterSecret("regcred", "cluster-token")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterSecret("signer", "cluster-key")); err != nil {
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

func wantReserved(t *testing.T, err error, what string) {
	t.Helper()
	if status(err) != http.StatusForbidden || !strings.Contains(err.Error(), "is reserved") || !strings.Contains(err.Error(), "cluster-admin") {
		t.Fatalf("%s: want 403 reserved for a cluster-admin, got %v", what, err)
	}
	if strings.Contains(err.Error(), "ask one of them") {
		t.Fatalf("%s: the refusal points at a namespace admin: %v", what, err)
	}
}

func roleBind(ns, name, role, user string) *v1.RoleBinding {
	return &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns},
		RoleRef:    v1.RoleRef{Kind: "ClusterRole", Name: role},
		Subjects:   []v1.Subject{{Kind: "User", Name: user}}}
}

// kevaso-system is reserved. A namespace admin bound there by a cluster-admin still cannot mint
// a token for plugin-juicefs or create a RoleBinding (or a Secret, or change the account), and
// someone RBAC allows to delete namespaces still cannot delete it. A cluster-admin can. A host's
// ?for= read keeps working. A RoleBinding in another namespace does not reach this one: get is
// still RBAC, and that binding only applies in its own namespace.
//
// Without the reservation, the admin's token and RoleBinding succeed (the built-in admin role
// grants both), a cluster-wide binding that is not cluster-admin mints the token, a control-plane
// host certificate mints it, and deleting the namespace is not this 403.
func TestKevasoSystemReservedForClusterAdmin(t *testing.T) {
	c := newCluster(t)
	sys := v1.PluginNamespace
	juice := operators.ServiceAccountName("juicefs")
	juiceNode := operators.ServiceAccountNodeName("juicefs")
	if err := c.admin.Create(c.ctx, ns(sys)); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, ns("web3")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ServiceAccount"},
		ObjectMeta: meta.ObjectMeta{Name: juice, Namespace: sys}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ServiceAccount"},
		ObjectMeta: meta.ObjectMeta{Name: juiceNode, Namespace: sys}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ServiceAccount"},
		ObjectMeta: meta.ObjectMeta{Name: "helper", Namespace: "web3"}}); err != nil {
		t.Fatal(err)
	}
	// The namespace admin, bound in kevaso-system by the admin socket. The same role in web3
	// must not reach kevaso-system.
	if err := c.admin.Create(c.ctx, roleBind(sys, "ada", "admin", "ada")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, roleBind("web3", "bob", "admin", "bob")); err != nil {
		t.Fatal(err)
	}
	// Not a cluster-admin: create on the token and on role bindings, in every namespace.
	if err := c.admin.Create(c.ctx, clusterRole("sys-tokens",
		v1.PolicyRule{Verbs: []string{"get"}, Resources: []string{"serviceaccounts"}},
		v1.PolicyRule{Verbs: []string{"create"}, Resources: []string{"serviceaccounts/token", "rolebindings"}},
	)); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterBind("erin-tokens", "sys-tokens", v1.Subject{Kind: "User", Name: "erin"})); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterRole("ns-delete", v1.PolicyRule{Verbs: []string{"get", "delete"}, Resources: []string{"namespaces"}})); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterBind("cara-ns", "ns-delete", v1.Subject{Kind: "User", Name: "cara"})); err != nil {
		t.Fatal(err)
	}
	// A cluster-admin by Policy.ClusterAdmin: the role, bound cluster-wide, not a certificate
	// whose role field says cluster-admin, and not the admin socket.
	if err := c.admin.Create(c.ctx, clusterBind("ops-admin", "cluster-admin", v1.Subject{Kind: "User", Name: "ops"})); err != nil {
		t.Fatal(err)
	}

	ada, doneAda := c.asUser(t, "ada")
	defer doneAda()
	bob, doneBob := c.asUser(t, "bob")
	defer doneBob()
	erin, doneErin := c.asUser(t, "erin")
	defer doneErin()
	cara, doneCara := c.asUser(t, "cara")
	defer doneCara()
	ops, doneOps := c.asUser(t, "ops")
	defer doneOps()

	tokPath, err := client.Path("ServiceAccount", sys, juice)
	if err != nil {
		t.Fatal(err)
	}
	tokPath += "/token"
	mint := func(cl *client.Client) (client.TokenResponse, error) {
		var tok client.TokenResponse
		err := cl.Call(c.ctx, http.MethodPost, tokPath, client.TokenRequest{}, &tok)
		return tok, err
	}

	// Reads stay with RBAC, and this get is what shows the binding is real: without it the
	// refusals below would be "no role", which they already are today.
	if err := ada.Get(c.ctx, "ServiceAccount", sys, juice, &v1.ServiceAccount{}); err != nil {
		t.Fatalf("namespace admin get: %v", err)
	}
	if err := bob.Get(c.ctx, "ServiceAccount", "web3", "helper", &v1.ServiceAccount{}); err != nil {
		t.Fatalf("admin of web3 get in web3: %v", err)
	}
	if err := bob.Get(c.ctx, "ServiceAccount", sys, juice, &v1.ServiceAccount{}); status(err) != http.StatusForbidden || strings.Contains(err.Error(), "is reserved") {
		t.Fatalf("RoleBinding in web3 get in %s: want RBAC 403, got %v", sys, err)
	}
	if _, err := mint(bob); status(err) != http.StatusForbidden {
		t.Fatalf("RoleBinding in web3 minting a token in %s: want 403, got %v", sys, err)
	}

	if tok, err := mint(ada); status(err) != http.StatusForbidden || tok.Token != "" {
		t.Fatalf("namespace admin minting %s: want 403 and no token, got %v %q", juice, err, tok.Token)
	} else {
		wantReserved(t, err, "namespace admin minting a token")
	}
	wantReserved(t, ada.Create(c.ctx, roleBind(sys, "more-admins", "admin", "mallory")), "namespace admin RoleBinding")
	sec := secretObj("note", nil, "not-for-ada")
	sec.Namespace = sys
	wantReserved(t, ada.Create(c.ctx, sec), "namespace admin Secret")
	var got v1.ServiceAccount
	if err := ada.Get(c.ctx, "ServiceAccount", sys, juice, &got); err != nil {
		t.Fatal(err)
	}
	got.Labels = map[string]string{"try": "change"}
	wantReserved(t, ada.Update(c.ctx, &got), "namespace admin update")

	if err := erin.Get(c.ctx, "ServiceAccount", sys, juice, &v1.ServiceAccount{}); err != nil {
		t.Fatalf("cluster-wide get: %v", err)
	}
	if tok, err := mint(erin); status(err) != http.StatusForbidden || tok.Token != "" {
		t.Fatalf("cluster-wide token grant: want 403 and no token, got %v %q", err, tok.Token)
	} else {
		wantReserved(t, err, "cluster-wide token grant")
	}

	cp, doneCP := c.asHost(t, "cp-reserve", "control-plane")
	defer doneCP()
	if tok, err := mint(cp); status(err) != http.StatusForbidden || tok.Token != "" {
		t.Fatalf("control-plane host minting a token: want 403 and no token, got %v %q", err, tok.Token)
	} else {
		wantReserved(t, err, "control-plane host")
	}

	if err := c.admin.Create(c.ctx, ns("scratch")); err != nil {
		t.Fatal(err)
	}
	if err := cara.Delete(c.ctx, "Namespace", "", "scratch"); err != nil {
		t.Fatalf("deleting an ordinary namespace: %v", err)
	}
	wantReserved(t, cara.Delete(c.ctx, "Namespace", "", sys), "deleting "+sys)
	if err := c.admin.Get(c.ctx, "Namespace", "", sys, &v1.Namespace{}); err != nil {
		t.Fatalf("namespace gone: %v", err)
	}

	if tok, err := mint(ops); err != nil || tok.Token == "" {
		t.Fatalf("cluster-admin token: %v %q", err, tok.Token)
	}
	if err := ops.Create(c.ctx, roleBind(sys, "from-ops", "viewer", "mallory")); err != nil {
		t.Fatalf("cluster-admin RoleBinding: %v", err)
	}
	if tok, err := mint(c.admin); err != nil || tok.Token == "" {
		t.Fatalf("admin socket token: %v %q", err, tok.Token)
	}

	if err := c.admin.Create(c.ctx, clusterSecret("bucket", "bucket-bytes")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterRole("juicefs-secrets", v1.PolicyRule{
		Verbs: []string{"get"}, Resources: []string{"clustersecrets/value"}, ResourceNames: []string{"bucket"},
	})); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, clusterBind("juicefs-secrets", "juicefs-secrets", saSubject(sys, juiceNode))); err != nil {
		t.Fatal(err)
	}
	hv := c.workerCert(t, "hv-reserve")
	v, err := c.readClusterValue(t, hv, "bucket", "for=juicefs&side=node")
	if err != nil || string(v.Value) != "bucket-bytes" {
		t.Fatalf("host ?for=juicefs&side=node: %q %v", v.Value, err)
	}
}
