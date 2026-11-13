package integration

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

// One approval, answered by several people at once, some yes, some no: exactly one answer
// counts, the others are told it was answered already (409), and the approval says the one that
// counted: never approved by one and denied by another, never answered twice.
func TestApprovalAnsweredAtOnce(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	if err := c.admin.Create(c.ctx, secretObj("gh-admin", nil, "ghp-admin")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, grantObj("dangerous", v1.GrantSpec{
		Secrets: []v1.GrantSecret{{Name: "gh-admin", Approval: &v1.ApprovalRule{Required: true}}}})); err != nil {
		t.Fatal(err)
	}
	node := silo("agent", "web3")
	node.Spec.Grants = []string{"dangerous"}
	if err := c.admin.Create(c.ctx, node); err != nil {
		t.Fatal(err)
	}
	node.Status.Host = "hv1"
	if err := c.admin.UpdateStatus(c.ctx, node); err != nil {
		t.Fatal(err)
	}
	eps := newEndpoints(t, c.host(t, "hv1"), "hv1")
	eps.add(t, node)
	people := []string{"ada", "bea", "cy", "dot", "eve", "fay"}
	var clients []*client.Client
	for _, p := range people {
		c.bind(t, p, "ClusterRole", "admin")
		clients = append(clients, c.as(t, p))
	}
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	go eps.ask(t, ctx, node, http.MethodGet, "/v1/secrets/gh-admin?for=5m", nil, 20*time.Millisecond, nil)
	var pending *v1.Approval
	for deadline := time.Now().Add(5 * time.Second); pending == nil && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		l, err := clients[0].List(c.ctx, "Approval", "web3")
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range l.Items {
			obj, _, _ := v1.Decode(raw)
			if a := obj.(*v1.Approval); a.Status.Phase == v1.ApprovalPending {
				pending = a
			}
		}
	}
	if pending == nil {
		t.Fatal("no pending approval")
	}
	errs := make([]error, len(clients))
	var start, wg sync.WaitGroup
	start.Add(1)
	for i, cl := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			verb := []string{"approve", "deny"}[i%2]
			start.Wait()
			errs[i] = cl.Call(c.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/web3/approvals/"+pending.Name+"/"+verb, client.ApprovalAnswer{Reason: people[i]}, nil)
		}()
	}
	start.Done()
	wg.Wait()
	winner := -1
	for i, err := range errs {
		switch {
		case err == nil:
			if winner >= 0 {
				t.Fatalf("both %s and %s answered", people[winner], people[i])
			}
			winner = i
		case status(err) != http.StatusConflict:
			t.Fatalf("%s: %v (want 409 for a second answer)", people[i], err)
		}
	}
	if winner < 0 {
		t.Fatal("nobody's answer counted")
	}
	var got v1.Approval
	if err := c.admin.Get(c.ctx, "Approval", "web3", pending.Name, &got); err != nil {
		t.Fatal(err)
	}
	want := map[int]string{0: v1.ApprovalApproved, 1: v1.ApprovalDenied}[winner%2]
	if got.Status.Phase != want || got.Status.AnsweredBy != people[winner] {
		t.Fatalf("approval says %s by %q; %s's %s counted", got.Status.Phase, got.Status.AnsweredBy, people[winner], want)
	}
}
