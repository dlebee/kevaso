package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// The definition, the policy and the roles, as an operator would apply them.
const databasesManifest = `
apiVersion: kevaso/v1
kind: KindDefinition
metadata: { name: databases.acme.dev }
spec:
  group: acme.dev
  version: v1
  names: { kind: Database, plural: databases, singular: database, shortNames: [db] }
  scope: Namespaced
  subresources: { status: {} }
  schema:
    type: object
    properties:
      spec:
        type: object
        properties:
          engine:   { type: string, enum: [postgres, mysql] }
          size:     { type: string, pattern: '^[0-9]+(Gi|Ti)$' }
          replicas: { type: integer, minimum: 1, maximum: 5, default: 1 }
        required: [engine]
        x-kevaso-validations:
          - { rule: "self.engine != 'mysql' || has(self.size)", message: "mysql needs a size" }
      status: { type: object, x-kevaso-preserve-unknown: true }
  printerColumns:
    - { name: Engine, jsonPath: .spec.engine }
    - { name: Ready,  jsonPath: '.status.conditions[?(@.type=="Ready")].status' }
    - { name: Endpoint, jsonPath: .status.endpoint }
`

// fromYAML decodes one YAML document into its kind's Go type.
func fromYAML(t *testing.T, doc string) meta.Object {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	o, _, err := v1.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func database(name, engine, size string) *v1.Unstructured {
	spec := map[string]any{"engine": engine}
	if size != "" {
		spec["size"] = size
	}
	return &v1.Unstructured{TypeMeta: meta.TypeMeta{APIVersion: "acme.dev/v1", Kind: "Database"},
		ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3"}, Fields: map[string]any{"spec": spec}}
}

// M17's "done when" (design §4.2): a KindDefinition adds a kind; a plugin's controller, built on
// the public api and sdk modules and running as its own identity, reconciles its objects and
// writes their status; a validation policy refuses a bad one; someone without a role on the
// kind's resource is refused, and it's audited.
func TestDefinedKindEndToEnd(t *testing.T) {
	c := newCluster(t)
	ctx := c.ctx
	if err := c.admin.Create(ctx, ns("web3")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(ctx, fromYAML(t, databasesManifest)); err != nil {
		t.Fatal(err)
	}
	// Roles: the controller reads databases and writes their status; ada edits them in web3.
	operator := &v1.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRole"}, ObjectMeta: meta.ObjectMeta{Name: "db-operator"},
		Rules: []v1.PolicyRule{
			{Verbs: []string{"get", "list", "watch"}, Resources: []string{"databases.acme.dev"}},
			{Verbs: []string{"update"}, Resources: []string{"databases.acme.dev/status"}},
		}}
	editor := &v1.Role{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Role"}, ObjectMeta: meta.ObjectMeta{Name: "db-editor", Namespace: "web3"},
		Rules: []v1.PolicyRule{{Verbs: []string{"get", "list", "watch", "create", "update", "delete"}, Resources: []string{"databases.acme.dev"}}}}
	opBinding := &v1.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: "db-operator"},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "db-operator"}, Subjects: []v1.Subject{{Kind: "User", Name: "db-operator"}}}
	policy := &v1.ValidationPolicy{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ValidationPolicy"}, ObjectMeta: meta.ObjectMeta{Name: "no-huge-databases"},
		Spec: v1.ValidationPolicySpec{Match: v1.PolicyMatch{Kinds: []string{"databases.acme.dev"}, Namespaces: []string{"web3"}},
			Validations: []v1.PolicyValidation{{Expression: "!has(object.spec.size) || !object.spec.size.endsWith('Ti')", Message: "databases in web3 are measured in Gi: ask for a Ti one"}}}}
	for _, o := range []meta.Object{operator, editor, opBinding, policy} {
		if err := c.admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	c.bind(t, "ada", "Role", "db-editor")
	op, ada, eve := c.as(t, "db-operator"), c.as(t, "ada"), c.as(t, "eve")

	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runDBController(runCtx, op)
	}()
	t.Cleanup(func() { stop(); <-done })

	// ada makes a database; the controller makes it Ready.
	if err := ada.Create(ctx, database("orders", "postgres", "10Gi")); err != nil {
		t.Fatal(err)
	}
	waitReady := func(gen int64) Database {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var db Database
			if err := ada.Get(ctx, "databases.acme.dev", "web3", "orders", &db); err != nil {
				t.Fatal(err)
			}
			if db.Status.ObservedGeneration == gen && meta.IsTrue(db.Status.Conditions, "Ready") {
				return db
			}
			if time.Now().After(deadline) {
				t.Fatalf("orders never got Ready at generation %d: %+v", gen, db)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	db := waitReady(1)
	if db.Spec.Replicas != 1 || db.Status.Endpoint != "postgres://orders.web3:5432" {
		t.Fatalf("reconciled: %+v", db)
	}
	// A change to the spec is a new generation, reconciled again.
	db.Spec.Size = "20Gi"
	if err := ada.Update(ctx, &db); err != nil {
		t.Fatal(err)
	}
	if db = waitReady(2); db.Spec.Size != "20Gi" {
		t.Fatalf("after update: %+v", db)
	}

	// The schema, its CEL rule and the policy each refuse what they should.
	for _, tc := range []struct {
		obj  *v1.Unstructured
		want string
	}{
		{database("big", "postgres", "2Ti"), "ValidationPolicy no-huge-databases: databases in web3 are measured in Gi"},
		{database("my", "mysql", ""), "spec: mysql needs a size"},
		{database("odd", "oracle", ""), "spec.engine: must be one of postgres, mysql"},
	} {
		if err := ada.Create(ctx, tc.obj); !client.IsInvalid(err) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.obj.Name, err, tc.want)
		}
	}

	// eve has no role on databases.acme.dev: refused, and audited.
	var got Database
	if err := eve.Get(ctx, "databases.acme.dev", "web3", "orders", &got); status(err) != http.StatusForbidden {
		t.Errorf("eve get: %v, want 403", err)
	}
	if _, err := eve.List(ctx, "db", "web3"); status(err) != http.StatusForbidden {
		t.Errorf("eve list: %v, want 403", err)
	}
	if err := eve.Create(ctx, database("mine", "postgres", "")); status(err) != http.StatusForbidden {
		t.Errorf("eve create: %v, want 403", err)
	}
	// Status and spec are separate powers: ada can't write status, the controller can't write spec.
	if err := ada.UpdateStatus(ctx, &db); status(err) != http.StatusForbidden {
		t.Errorf("ada writing status: %v, want 403", err)
	}
	if err := op.Update(ctx, &db); status(err) != http.StatusForbidden {
		t.Errorf("the controller writing spec: %v, want 403", err)
	}
	audited := false
	for _, e := range c.audit.Entries() {
		if e.User == "eve" && !e.Allowed && e.Resource == "databases.acme.dev" && e.Verb == "get" {
			audited = true
		}
	}
	if !audited {
		t.Error("eve's refusal isn't in the audit log")
	}

	// The definition stays while a database is left.
	if err := c.admin.Delete(ctx, "KindDefinition", "", "databases.acme.dev"); !client.IsConflict(err) {
		t.Errorf("deleting the definition with orders left: %v, want Conflict", err)
	}
}

// kvo works with defined kinds like built-ins: apply, get (with the printer columns), get kinds,
// describe, watch, delete.
func TestKvoWithDefinedKinds(t *testing.T) {
	h := newHarness(t)
	h.ok("apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: demo }\n", "apply", "-f", "-")
	// The definition and its objects in one file: kvo learns the kind as soon as it exists.
	out := h.ok(databasesManifest+`---
apiVersion: acme.dev/v1
kind: Database
metadata: { name: orders, namespace: demo }
spec: { engine: postgres, size: 10Gi }
---
apiVersion: acme.dev/v1
kind: Database
metadata: { name: carts }
spec: { engine: mysql, size: 5Gi, replicas: 2 }
`, "apply", "-f", "-", "-n", "demo")
	for _, want := range []string{"kinddefinition/databases.acme.dev created", "databases.acme.dev/orders created", "databases.acme.dev/carts created"} {
		if !strings.Contains(out, want) {
			t.Fatalf("apply:\n%s\nwant %q", out, want)
		}
	}
	if out := h.ok(`apiVersion: acme.dev/v1
kind: Database
metadata: { name: orders, namespace: demo }
spec: { engine: postgres, size: 10Gi, replicas: 1 }
`, "apply", "-f", "-"); !strings.Contains(out, "unchanged") { // replicas: the default, now stored
		t.Errorf("apply again:\n%s", out)
	}

	out = h.ok("", "get", "kinds")
	for _, want := range []string{"databases.acme.dev", "acme.dev/v1", "Database", "silos", "kevaso/v1", "kinddefinitions"} {
		if !strings.Contains(out, want) {
			t.Errorf("get kinds:\n%s\nwant %q", out, want)
		}
	}
	out = h.ok("", "get", "db", "-n", "demo")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || strings.Join(strings.Fields(lines[0]), " ") != "NAME ENGINE READY ENDPOINT AGE" ||
		!strings.HasPrefix(strings.Join(strings.Fields(lines[1]), " "), "carts mysql - - ") {
		t.Errorf("get db:\n%s", out)
	}
	if out := h.ok("", "get", "databases.acme.dev", "-A"); !strings.Contains(out, "NAMESPACE") || !strings.Contains(out, "orders") {
		t.Errorf("get -A:\n%s", out)
	}
	if out := h.ok("", "get", "database", "orders", "-n", "demo", "-o", "yaml"); !strings.Contains(out, "replicas: 1") || !strings.Contains(out, "apiVersion: acme.dev/v1") {
		t.Errorf("get -o yaml (the default replicas):\n%s", out)
	}
	if out := h.ok("", "describe", "db", "carts", "-n", "demo"); !strings.Contains(out, "Database (acme.dev/v1)") || !strings.Contains(out, "engine: mysql") {
		t.Errorf("describe:\n%s", out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wout, _, _ := h.kvo(ctx, "", "watch", "db", "-n", "demo")
	if !strings.Contains(wout, "databases.acme.dev/demo/orders") {
		t.Errorf("watch:\n%s", wout)
	}

	if _, errs, code := h.kvo(context.Background(), "", "delete", "kinddefinition", "databases.acme.dev"); code == 0 || !strings.Contains(errs, "still has 2 object") {
		t.Errorf("delete the definition in use: %d %s", code, errs)
	}
	h.ok("", "delete", "db", "orders", "-n", "demo")
	h.ok("", "delete", "db", "carts", "-n", "demo")
	h.ok("", "delete", "kd", "databases.acme.dev")
	if _, errs, code := h.kvo(context.Background(), "", "get", "db"); code == 0 || !strings.Contains(errs, "unknown kind") {
		t.Errorf("get after the definition went: %d %s", code, errs)
	}
}
