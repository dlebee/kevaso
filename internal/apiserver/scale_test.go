package apiserver_test

import (
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

// The scale subresource reads and sets the replica count as an update of the object (schema
// bounds apply, generation moves), and transition rules see the stored object as oldSelf.
func TestScaleAndTransitionRules(t *testing.T) {
	c, ctx := setup(t)
	d := dbDefinition(t, strings.Replace(dbSchema, `"engine": {"type": "string", "enum": ["postgres", "mysql"]}`,
		`"engine": {"type": "string", "enum": ["postgres", "mysql"], "x-kevaso-validations": [{"rule": "self == oldSelf", "message": "engine can't change"}]}`, 1))
	d.Spec.Schema.Properties["status"] = v1.JSONSchema{Type: "object", Properties: map[string]v1.JSONSchema{"replicas": {Type: "integer"}}}
	d.Spec.Subresources.Scale = &v1.ScaleSubresource{SpecReplicasPath: ".spec.replicas", StatusReplicasPath: ".status.replicas"}
	if err := c.Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	o := db("orders", map[string]any{"engine": "postgres"})
	if err := c.Create(ctx, o); err != nil {
		t.Fatal(err)
	}
	sc, err := c.GetScale(ctx, "databases.acme.dev", "dev", "orders")
	if err != nil || sc.Spec.Replicas != 1 || sc.Status.Replicas != 0 || sc.Kind != "Scale" {
		t.Fatalf("scale: %+v %v", sc, err)
	}
	sc.Spec.Replicas = 3
	if err := c.UpdateScale(ctx, "databases.acme.dev", sc); err != nil || sc.Spec.Replicas != 3 {
		t.Fatalf("scaling to 3: %+v %v", sc, err)
	}
	var got v1.Unstructured
	if err := c.Get(ctx, "databases.acme.dev", "dev", "orders", &got); err != nil {
		t.Fatal(err)
	}
	if spec := got.Fields["spec"].(map[string]any); spec["replicas"] != float64(3) && spec["replicas"] != int64(3) || got.Generation != 2 {
		t.Errorf("after scale: spec %v, generation %d", spec, got.Generation)
	}
	sc.Spec.Replicas = 0
	if err := c.UpdateScale(ctx, "databases.acme.dev", sc); !client.IsInvalid(err) || !strings.Contains(err.Error(), "minimum") {
		t.Errorf("below the schema's minimum: %v", err)
	}
	stale := *sc
	stale.ResourceVersion, stale.Spec.Replicas = "1", 2
	if err := c.UpdateScale(ctx, "databases.acme.dev", &stale); code(err) != http.StatusConflict {
		t.Errorf("a stale scale: %v", err)
	}
	// oldSelf: engine can't change.
	got.Fields["spec"].(map[string]any)["engine"] = "mysql"
	got.Fields["spec"].(map[string]any)["size"] = "5Gi"
	if err := c.Update(ctx, &got); !client.IsInvalid(err) || !strings.Contains(err.Error(), "engine can't change") {
		t.Errorf("changing an immutable field: %v", err)
	}
	// Kinds without scale have no /scale.
	if err := c.Call(ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/dev/silos/x/scale", nil, nil); code(err) != http.StatusNotFound {
		t.Errorf("a built-in's /scale: %v", err)
	}
}
