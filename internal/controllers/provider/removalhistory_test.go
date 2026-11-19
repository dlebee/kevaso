package provider_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/provider"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// A removal recorded under one restore history is not resumed under another: the record is
// dropped and the volume stays. A removal recorded under the history now open is still deleted.
func TestARemovalFromAnotherHistoryIsDroppedAndTheVolumeKept(t *testing.T) {
	x := newK037(t)
	kept := x.silo("kept", "w1")
	handle := kept.Status.Volumes[0].Handle
	kept.Spec.Volumes = nil
	x.must(x.c.Update(x.ctx, kept))
	kept = x.get("kept")
	kept.Status.Volumes = nil
	x.must(x.c.UpdateStatus(x.ctx, kept))
	o, err := x.st.Get(x.ctx, store.Key{Kind: provider.VolumeRecordKind, Namespace: "d", Name: kept.UID + ".data"})
	x.must(err)
	rec, err := json.Marshal(map[string]any{
		"name": "data", "class": kplugintest.ClassBlock, "handle": handle, "region": "r",
		"attachedTo": "w1", "removing": true, "history": "h1",
	})
	x.must(err)
	if _, err := x.st.Update(x.ctx, o.Key, rec, o.Revision); err != nil {
		t.Fatal(err)
	}

	v := x.volumes()
	v.Gate = &v1.RestoreGate{Spec: v1.RestoreGateSpec{History: "h2"}}
	mark := len(x.fake.CallLog())
	if _, err := v.Reconcile(x.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: "kept"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range x.callsOn(mark, handle) {
		if strings.HasPrefix(c, "delete-volume ") {
			t.Fatalf("a removal from history h1 was resumed under h2: %v", x.callsOn(mark, handle))
		}
	}
	if _, vols, _ := x.fake.Snapshot(); vols[handle].Handle == "" {
		t.Fatal("the volume was deleted")
	}
	if _, err := x.st.Get(x.ctx, o.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("removal record from h1: %v", err)
	}

	same := x.silo("same", "w2")
	own := same.Status.Volumes[0].Handle
	v = x.volumes()
	v.Gate = &v1.RestoreGate{Spec: v1.RestoreGateSpec{History: "h2"}}
	x.must(x.c.Delete(x.ctx, "Silo", "d", "same"))
	mark = len(x.fake.CallLog())
	for range 4 {
		if _, err := v.Reconcile(x.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: "same"}); err != nil {
			t.Fatal(err)
		}
	}
	deleted := false
	for _, c := range x.callsOn(mark, own) {
		if strings.HasPrefix(c, "delete-volume ") {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("a removal under the open history was not done: %v", x.callsOn(mark, own))
	}
}
