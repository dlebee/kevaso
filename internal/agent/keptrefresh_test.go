package agent_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// Found on the machines (metal.md, 559f405 and the ninth batch): the Host's KeptSilos still named
// copies removed by hand hours before. What it lists is what the runtimes hold now: a kept copy
// the runtime no longer has leaves the list at the next pass, and with none left the condition
// goes.
func TestKeptSilosListsOnlyTheCopiesTheRuntimesStillHold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	rt := fake.NewStrict("hv1", nil)
	// Two copies the control plane doesn't know, whose deletes this host never saw: kept.
	a1 := kri.ID{Namespace: "dev", Name: "stuckstop", UID: "1111aaaa-0000-0000-0000-000000000000"}
	b2 := kri.ID{Namespace: "dev", Name: "vmresetback", UID: "2222bbbb-0000-0000-0000-000000000000"}
	for _, id := range []kri.ID{a1, b2} {
		if err := rt.Create(ctx, kri.Spec{ID: id, Image: "ubuntu-24.04"}); err != nil {
			t.Fatal(err)
		}
		if err := rt.Start(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	a := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clk, Log: t.Logf}
	agent.RunForTest(t, ctx, a)
	kept := func() *meta.Condition {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", "hv1", &h); err != nil {
			t.Fatal(err)
		}
		return meta.FindCondition(h.Status.Conditions, agent.ConditionKeptSilos)
	}
	until := func(what string, cond func(k *meta.Condition) bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !cond(kept()); {
			if time.Now().After(deadline) {
				t.Fatalf("never: %s; KeptSilos is %+v", what, kept())
			}
			time.Sleep(10 * time.Millisecond)
			clk.Step(100 * time.Millisecond) // the agent's passes (fence.CheckEvery) come as the clock moves
		}
	}
	names := func(k *meta.Condition, uids ...string) bool {
		if k == nil || k.Status != meta.ConditionTrue {
			return false
		}
		n := 0
		for _, u := range []string{a1.UID[:8], b2.UID[:8]} {
			if strings.Contains(k.Message, u) {
				n++
			}
		}
		for _, u := range uids {
			if !strings.Contains(k.Message, u[:8]) {
				return false
			}
		}
		return n == len(uids)
	}
	until("both kept copies listed", func(k *meta.Condition) bool { return names(k, a1.UID, b2.UID) })

	if err := rt.Delete(ctx, a1); err != nil { // removed by hand
		t.Fatal(err)
	}
	until("the copy removed by hand leaves the list, the other stays", func(k *meta.Condition) bool { return names(k, b2.UID) })

	if err := rt.Delete(ctx, b2); err != nil {
		t.Fatal(err)
	}
	until("with none left, the condition goes", func(k *meta.Condition) bool { return k == nil })
}
