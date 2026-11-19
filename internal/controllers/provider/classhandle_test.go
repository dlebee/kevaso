package provider_test

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// A handle recorded for one class is not used when the spec names that volume under another.
func TestAHandleIsNotUsedUnderAnotherClass(t *testing.T) {
	x := newK037(t)
	s := x.silo("db", "w1")
	handle := s.Status.Volumes[0].Handle
	o, err := x.st.Get(x.ctx, store.Key{Kind: "Silo", Namespace: "d", Name: "db"})
	x.must(err)
	var cur v1.Silo
	x.must(json.Unmarshal(o.Data, &cur))
	cur.Spec.Volumes[0].Class = kplugintest.ClassShare
	b, err := json.Marshal(&cur)
	x.must(err)
	if _, err := x.st.Update(x.ctx, o.Key, b, o.Revision); err != nil {
		t.Fatal(err)
	}
	mark := len(x.fake.CallLog())
	x.reconcile("db")
	got := x.get("db").Status.Volumes
	if len(got) != 1 || got[0].Class != kplugintest.ClassBlock || got[0].Handle != handle || !strings.Contains(got[0].Message, "not used under") {
		t.Fatalf("handle used under the other class: %+v", got)
	}
	for _, c := range x.fake.CallLog()[mark:] {
		if strings.Contains(c, handle) || strings.Contains(c, s.UID+"/data") {
			t.Fatalf("plugin call for the handle: %s", c)
		}
	}
}
