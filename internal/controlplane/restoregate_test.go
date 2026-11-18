package controlplane

import (
	"context"
	"encoding/json"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

func TestOpenRestoreGateRecordsTheStatement(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := WriteRestoreHosts(dir, false, []string{"hv9"}); err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"},
		ObjectMeta: meta.ObjectMeta{Name: "cp-1"}, Spec: v1.HostSpec{InternalIP: "10.0.0.1"}}
	b, _ := json.Marshal(h)
	if _, err := st.Create(ctx, store.Key{Kind: "Host", Name: "cp-1"}, b); err != nil {
		t.Fatal(err)
	}
	cfg := Config{DataDir: dir, Clock: clock.Real{}}
	if err := openRestoreGate(ctx, st, cfg, ClusterIdentity{History: "h2", Epoch: 2}); err != nil {
		t.Fatal(err)
	}
	if err := openRestoreGate(ctx, st, cfg, ClusterIdentity{History: "h3", Epoch: 3}); err != nil {
		t.Fatal(err)
	}
	o, err := st.Get(ctx, store.Key{Kind: "RestoreGate", Name: v1.RestoreGateName})
	if err != nil {
		t.Fatal(err)
	}
	var g v1.RestoreGate
	if err := json.Unmarshal(o.Data, &g); err != nil {
		t.Fatal(err)
	}
	if g.Spec.History != "h3" || g.Spec.NoHostsAdded || len(g.Spec.HostsAdded) != 1 || g.Spec.HostsAdded[0] != "hv9" {
		t.Fatalf("statement: %+v", g.Spec)
	}
	if len(g.Spec.Required) != 1 || g.Spec.Required[0] != "cp-1" || g.Spec.Started.IsZero() {
		t.Fatalf("required: %+v", g.Spec)
	}
	both := t.TempDir()
	if err := WriteRestoreHosts(both, true, []string{"hv9"}); err != nil {
		t.Fatal(err)
	}
	if err := openRestoreGate(ctx, st, Config{DataDir: both, Clock: clock.Real{}}, ClusterIdentity{History: "h4"}); err == nil {
		t.Fatal("both forms of the statement were accepted")
	}
}
