package apiserver_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

const dbSchema = `{
  "type": "object",
  "properties": {
    "spec": {
      "type": "object",
      "properties": {
        "engine": {"type": "string", "enum": ["postgres", "mysql"]},
        "size":   {"type": "string"},
        "replicas": {"type": "integer", "minimum": 1, "default": 1}
      },
      "required": ["engine"],
      "x-kevaso-validations": [{"rule": "self.engine != 'mysql' || has(self.size)", "message": "mysql needs a size"}]
    },
    "status": {"type": "object", "x-kevaso-preserve-unknown": true}
  }
}`

func dbDefinition(t *testing.T, schema string) *v1.KindDefinition {
	t.Helper()
	d := &v1.KindDefinition{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "KindDefinition"}, ObjectMeta: meta.ObjectMeta{Name: "databases.acme.dev"},
		Spec: v1.KindDefinitionSpec{Group: "acme.dev", Version: "v1", Scope: v1.Namespaced,
			Names:          v1.KindNames{Kind: "Database", Plural: "databases", ShortNames: []string{"db"}},
			Subresources:   &v1.KindSubresources{Status: &struct{}{}},
			PrinterColumns: []v1.PrinterColumn{{Name: "Engine", JSONPath: ".spec.engine"}}}}
	if err := json.Unmarshal([]byte(schema), &d.Spec.Schema); err != nil {
		t.Fatal(err)
	}
	return d
}

func db(name string, spec map[string]any) *v1.Unstructured {
	return &v1.Unstructured{TypeMeta: meta.TypeMeta{APIVersion: "acme.dev/v1", Kind: "Database"},
		ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"}, Fields: map[string]any{"spec": spec}}
}

func TestDefinedKindLifecycle(t *testing.T) {
	c, ctx := setup(t)
	if err := c.Create(ctx, db("x", map[string]any{"engine": "postgres"})); err == nil {
		t.Fatal("created an object of a kind nobody defined")
	}
	d := dbDefinition(t, dbSchema)
	if err := c.Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	rs, err := c.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range rs {
		if r.Resource == "databases.acme.dev" {
			found = r.Kind == "Database" && r.Status && r.Scope == v1.Namespaced && len(r.PrinterColumns) == 1
		}
	}
	if !found {
		t.Fatalf("discovery: %+v", rs)
	}

	// Create: defaults, generation 1, status dropped (it's the controllers').
	o := db("main", map[string]any{"engine": "postgres"})
	o.Fields["status"] = map[string]any{"phase": "Faked"}
	if err := c.Create(ctx, o); err != nil {
		t.Fatal(err)
	}
	if o.Generation != 1 || o.UID == "" || o.GetString("spec", "engine") != "postgres" {
		t.Fatalf("created: %+v", o)
	}
	if v, _ := o.Get("spec", "replicas"); v != int64(1) {
		t.Errorf("default replicas: %v (%T)", v, v)
	}
	if _, ok := o.Get("status"); ok {
		t.Error("create kept status")
	}

	// Refused: schema, CEL rule, unknown fields, unknown metadata, wrong kind.
	for name, bad := range map[string]*v1.Unstructured{
		"enum":     db("bad1", map[string]any{"engine": "oracle"}),
		"rule":     db("bad2", map[string]any{"engine": "mysql"}),
		"unknown":  db("bad3", map[string]any{"engine": "postgres", "color": "blue"}),
		"required": db("bad4", map[string]any{}),
	} {
		if err := c.Create(ctx, bad); !client.IsInvalid(err) {
			t.Errorf("%s: %v, want Invalid", name, err)
		}
	}
	raw := `{"apiVersion": "acme.dev/v1", "kind": "Database", "metadata": {"name": "m", "namespace": "dev", "colour": "red"}, "spec": {"engine": "postgres"}}`
	if err := c.Call(ctx, http.MethodPost, "/apis/acme.dev/v1/namespaces/dev/databases", json.RawMessage(raw), nil); !client.IsInvalid(err) {
		t.Errorf("unknown metadata field: %v, want Invalid", err)
	}

	// Get, by every name the client knows it by.
	for _, name := range []string{"databases.acme.dev", "databases", "Database", "db", "database"} {
		var got v1.Unstructured
		if err := c.Get(ctx, name, "dev", "main", &got); err != nil || got.UID != o.UID {
			t.Errorf("get as %q: %v", name, err)
		}
	}

	// Status through /status doesn't move generation; a main write keeps status and bumps it.
	o.Fields["status"] = map[string]any{"phase": "Ready"}
	if err := c.UpdateStatus(ctx, o); err != nil {
		t.Fatal(err)
	}
	if o.Generation != 1 || o.GetString("status", "phase") != "Ready" {
		t.Fatalf("after status: %+v", o)
	}
	stale := o.ResourceVersion
	o.Set("10Gi", "spec", "size")
	o.Fields["status"] = map[string]any{"phase": "Overwritten"}
	if err := c.Update(ctx, o); err != nil {
		t.Fatal(err)
	}
	if o.Generation != 2 || o.GetString("status", "phase") != "Ready" {
		t.Fatalf("after spec update: generation %d, status %v", o.Generation, o.Fields["status"])
	}
	o.ResourceVersion = stale
	if err := c.Update(ctx, o); !client.IsConflict(err) {
		t.Errorf("stale update: %v, want Conflict", err)
	}

	// A list carries the kind's apiVersion.
	l, err := c.List(ctx, "db", "dev")
	if err != nil || len(l.Items) != 1 {
		t.Fatalf("list: %v %d", err, len(l.Items))
	}
	if obj, _, err := v1.Decode(l.Items[0]); err != nil || obj.(*v1.Unstructured).GetString("spec", "size") != "10Gi" {
		t.Errorf("decoded item: %v %+v", err, obj)
	}

	// The definition can't go while objects are left; changing it never makes them unreadable.
	if err := c.Delete(ctx, "KindDefinition", "", d.Name); !client.IsConflict(err) || !strings.Contains(err.Error(), "still has 1 object") {
		t.Errorf("deleting a definition in use: %v", err)
	}
	var cur v1.KindDefinition
	if err := c.Get(ctx, "KindDefinition", "", d.Name, &cur); err != nil {
		t.Fatal(err)
	}
	stricter := dbDefinition(t, strings.Replace(dbSchema, `"required": ["engine"]`, `"required": ["engine", "owner"]`, 1))
	stricter.Spec.Schema.Properties["spec"].Properties["owner"] = v1.JSONSchema{Type: "string"}
	stricter.ResourceVersion = cur.ResourceVersion
	if err := c.Update(ctx, stricter); err != nil {
		t.Fatal(err)
	}
	var again v1.Unstructured
	if err := c.Get(ctx, "databases.acme.dev", "dev", "main", &again); err != nil {
		t.Fatalf("read after the schema changed: %v", err)
	}
	if err := c.UpdateStatus(ctx, &again); err != nil { // status writes check status only
		t.Errorf("status write after the schema changed: %v", err)
	}
	if err := c.Update(ctx, &again); !client.IsInvalid(err) || !strings.Contains(err.Error(), "spec.owner: required") {
		t.Errorf("spec write after the schema changed: %v, want spec.owner required", err)
	}
	// What can't change, can't.
	moved := dbDefinition(t, dbSchema)
	moved.Spec.Scope = v1.Cluster
	_ = c.Get(ctx, "KindDefinition", "", d.Name, &cur)
	moved.ResourceVersion = cur.ResourceVersion
	if err := c.Update(ctx, moved); !client.IsInvalid(err) || !strings.Contains(err.Error(), "spec.scope can't change") {
		t.Errorf("changing scope: %v", err)
	}

	// Finalizers: delete marks, removing the last one deletes.
	again.Finalizers = []string{"acme.dev/cleanup"}
	again.Set("someone", "spec", "owner")
	if err := c.Update(ctx, &again); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, "db", "dev", "main"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "db", "dev", "main", &again); err != nil || again.DeletionTimestamp == nil {
		t.Fatalf("after delete with a finalizer: %v %+v", err, again.ObjectMeta)
	}
	again.Finalizers = nil
	if err := c.Update(ctx, &again); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "db", "dev", "main", &again); !client.IsNotFound(err) {
		t.Fatalf("after the last finalizer: %v", err)
	}
	if err := c.Delete(ctx, "KindDefinition", "", d.Name); err != nil {
		t.Errorf("deleting an unused definition: %v", err)
	}
	if err := c.Get(ctx, "databases.acme.dev", "dev", "main", &again); err == nil {
		t.Error("the kind is still served after its definition went")
	}
}

func TestDefinitionsCantShadowBuiltins(t *testing.T) {
	c, ctx := setup(t)
	d := dbDefinition(t, dbSchema)
	d.Name, d.Spec.Names = "silos.acme.dev", v1.KindNames{Kind: "Silo", Plural: "silos"}
	if err := c.Create(ctx, d); !client.IsInvalid(err) || !strings.Contains(err.Error(), "can't shadow") {
		t.Errorf("a definition shadowing silos: %v", err)
	}
	d = dbDefinition(t, dbSchema)
	d.Name, d.Spec.Group = "databases.kevaso", "kevaso"
	if err := c.Create(ctx, d); !client.IsInvalid(err) {
		t.Errorf("a definition in kevaso: %v", err)
	}
	// Built-ins keep strict decoding.
	raw := `{"apiVersion": "kevaso/v1", "kind": "Silo", "metadata": {"name": "s", "namespace": "dev"}, "spec": {"runtime": "docker", "image": "x", "colour": "red"}}`
	if err := c.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos", json.RawMessage(raw), nil); !client.IsInvalid(err) {
		t.Errorf("unknown field on a built-in: %v", err)
	}
}

func TestPoliciesOnBuiltinKinds(t *testing.T) {
	c, ctx := setup(t)
	mut := &v1.MutationPolicy{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "MutationPolicy"}, ObjectMeta: meta.ObjectMeta{Name: "label-runtime"},
		Spec: v1.MutationPolicySpec{Match: v1.PolicyMatch{Kinds: []string{"Silo"}}, Mutations: []v1.Mutation{
			{Field: "metadata.labels.acme.dev/runtime", Value: "object.spec.runtime"},
			{Field: "spec.runtime", Value: "'docker'", When: "object.metadata.namespace == 'dev' && object.spec.runtime == 'podman'"},
		}}}
	val := &v1.ValidationPolicy{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ValidationPolicy"}, ObjectMeta: meta.ObjectMeta{Name: "no-ch-in-dev"},
		Spec: v1.ValidationPolicySpec{Match: v1.PolicyMatch{Kinds: []string{"silos"}, Namespaces: []string{"dev"}}, Validations: []v1.PolicyValidation{
			{Expression: "object.spec.runtime != 'cloud-hypervisor'", Message: "silos in dev may not use cloud-hypervisor"},
		}}}
	for _, p := range []meta.Object{mut, val} {
		if err := c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Create(ctx, newSilo("vm")); !client.IsInvalid(err) || !strings.Contains(err.Error(), "ValidationPolicy no-ch-in-dev: silos in dev may not use cloud-hypervisor") {
		t.Fatalf("a silo the policy forbids: %v", err)
	}
	s := newSilo("ok")
	s.Spec.Runtime = "podman"
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	if s.Spec.Runtime != "docker" || s.Labels["acme.dev/runtime"] != "podman" {
		t.Errorf("mutated silo: runtime %q, labels %v", s.Spec.Runtime, s.Labels)
	}
	// A mutation that sets a field the kind doesn't have fails, naming the policy's effect.
	bad := &v1.MutationPolicy{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "MutationPolicy"}, ObjectMeta: meta.ObjectMeta{Name: "typo"},
		Spec: v1.MutationPolicySpec{Match: v1.PolicyMatch{Kinds: []string{"Silo"}}, Mutations: []v1.Mutation{{Field: "spec.runtme", Value: "'docker'"}}}}
	if err := c.Create(ctx, bad); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, newSilo("other")); !client.IsInvalid(err) || !strings.Contains(err.Error(), "after mutation policies") {
		t.Errorf("a mutation to a field silos don't have: %v", err)
	}
	// Policies themselves are refused when they don't compile, and never apply to RBAC.
	broken := *val
	broken.Name, broken.Spec.Validations = "broken", []v1.PolicyValidation{{Expression: "object.spec. =="}}
	if err := c.Create(ctx, &broken); !client.IsInvalid(err) {
		t.Errorf("a policy that doesn't compile: %v", err)
	}
	rbacPol := *val
	rbacPol.Name, rbacPol.Spec.Match.Kinds = "rbac", []string{"ClusterRole"}
	if err := c.Create(ctx, &rbacPol); !client.IsInvalid(err) {
		t.Errorf("a policy on ClusterRoles: %v", err)
	}
}
