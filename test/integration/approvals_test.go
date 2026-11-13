package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Design §8.7 through the real API and the host's broker: a secret whose grant needs a person's yes
// waits as a pending Approval until a person with approve on that secret answers; approved access
// lasts its time; a no and an unanswered request fail the call, saying which; a service account,
// an editor and a host can never answer; approvals are never written through the plain API; a
// grant without approval works as before.
func TestApprovals(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	for _, s := range []*v1.Secret{secretObj("gh-admin", map[string]string{"danger": "high"}, "ghp-admin"), secretObj("db-password", nil, "pw")} {
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	key := secretObj("deploy-key", nil, "")
	key.Spec.Type, key.Spec.Generate = v1.SecretEd25519, true
	if err := c.admin.Create(c.ctx, key); err != nil {
		t.Fatal(err)
	}
	yes := &v1.ApprovalRule{Required: true}
	if err := c.admin.Create(c.ctx, grantObj("dangerous", v1.GrantSpec{
		Secrets:    []v1.GrantSecret{{Name: "gh-admin", Approval: yes}, {Name: "db-password"}},
		Operations: &v1.GrantOperations{Sign: &v1.SignOperation{KeyRef: "deploy-key", Approval: yes}},
	})); err != nil {
		t.Fatal(err)
	}
	// Admission: approval with a delivery that puts the value in the silo is refused.
	bad := grantObj("bad", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db-password", Deliver: v1.DeliverFile, Approval: yes}}})
	if err := c.admin.Create(c.ctx, bad); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "approval works with deliver: broker or inject") {
		t.Fatalf("approval on a file delivery: %v", err)
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
	hv1Client := c.host(t, "hv1")
	eps := newEndpoints(t, hv1Client, "hv1")
	eps.add(t, node)
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()

	// People: ada (admin: approve on every secret), ed (editor: no approve), dee (approve on
	// secrets labelled danger=high only).
	if err := c.admin.Create(c.ctx, &v1.Role{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Role"},
		ObjectMeta: meta.ObjectMeta{Name: "approver", Namespace: "web3"}, Rules: []v1.PolicyRule{
			{Verbs: []string{v1.VerbApprove}, Resources: []string{"secrets"}, Selector: map[string]string{"danger": "high"}},
			{Verbs: []string{"get", "list"}, Resources: []string{"approvals"}},
		}}); err != nil {
		t.Fatal(err)
	}
	c.bind(t, "ada", "ClusterRole", "admin")
	c.bind(t, "ed", "ClusterRole", "editor")
	c.bind(t, "dee", "Role", "approver")
	ada, ed, dee := c.as(t, "ada"), c.as(t, "ed"), c.as(t, "dee")
	// A service account with the admin role still can't answer.
	if err := c.admin.Create(c.ctx, &v1.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ServiceAccount"},
		ObjectMeta: meta.ObjectMeta{Name: "bot", Namespace: "web3"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "bot", Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "admin"},
		Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: "bot"}}}); err != nil {
		t.Fatal(err)
	}
	var tok client.TokenResponse
	if err := c.admin.Call(c.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/web3/serviceaccounts/bot/token", client.TokenRequest{}, &tok); err != nil {
		t.Fatal(err)
	}
	bot, _ := client.NewTLS(c.url, c.ca, nil, nil)
	bot.Token = func(context.Context) (string, error) { return tok.Token, nil }

	answer := func(who *client.Client, name, verb, reason string) error {
		return who.Call(c.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/web3/approvals/"+name+"/"+verb, client.ApprovalAnswer{Reason: reason}, nil)
	}
	pendingOf := func(use, secret string) *v1.Approval {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			l, err := ada.List(c.ctx, "Approval", "web3")
			if err != nil {
				t.Fatal(err)
			}
			for _, raw := range l.Items {
				obj, _, err := v1.Decode(raw)
				if err != nil {
					t.Fatal(err)
				}
				a := obj.(*v1.Approval)
				if a.Spec.Use == use && a.Spec.Secret == secret && a.Status.Phase == v1.ApprovalPending {
					return a
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("no pending approval for %s %s", use, secret)
		return nil
	}

	// A secret without approval in the same grant: straight through.
	if a := eps.call(t, node, http.MethodGet, "/v1/secrets/db-password", nil); a.code != 200 || a.body != "pw" {
		t.Fatalf("ungated secret: %d %q", a.code, a.body)
	}

	// 1. The silo asks for gh-admin: 428 with the approval's name, and it asks again until answered.
	got := make(chan epAnswer, 1)
	var waitedOn string
	go func() {
		got <- eps.ask(t, ctx, node, http.MethodGet, "/v1/secrets/gh-admin?for=20m", nil, 20*time.Millisecond, func(name string) { waitedOn = name })
	}()
	a := pendingOf(v1.ApprovalForSecret, "gh-admin")
	if a.Spec.Silo != "agent" || a.Spec.Grant != "dangerous" || a.Spec.For != "20m0s" || a.Spec.ExpiresAt.IsZero() {
		t.Fatalf("approval = %+v", a.Spec)
	}
	select {
	case r := <-got:
		t.Fatalf("the call didn't wait: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}

	// 2. Who can't answer: an editor, a service account (even an admin one), a host.
	if err := answer(ed, a.Name, "approve", ""); status(err) != http.StatusForbidden {
		t.Fatalf("editor approved: %v", err)
	}
	if err := answer(bot, a.Name, "approve", ""); status(err) != http.StatusForbidden || !strings.Contains(err.Error(), "only people") {
		t.Fatalf("service account approved: %v", err)
	}
	if err := answer(hv1Client, a.Name, "approve", ""); status(err) != http.StatusForbidden {
		t.Fatalf("host approved: %v", err)
	}
	// Nor can anyone write approvals through the plain API.
	forged := *a
	forged.Status = v1.ApprovalStatus{Phase: v1.ApprovalApproved}
	if err := c.admin.Update(c.ctx, &forged); status(err) != http.StatusMethodNotAllowed {
		t.Fatalf("approval written through the API: %v", err)
	}

	// 3. dee may approve secrets labelled danger=high: the call goes through.
	if err := answer(dee, a.Name, "approve", ""); err != nil {
		t.Fatal(err)
	}
	r := <-got
	if r.code != 200 || r.body != "ghp-admin" || waitedOn != a.Name {
		t.Fatalf("after approval: %d %q (waited on %q)", r.code, r.body, waitedOn)
	}
	if err := answer(ada, a.Name, "deny", ""); status(err) != http.StatusConflict {
		t.Fatalf("second answer: %v", err)
	}
	// While access lasts, the silo doesn't ask again.
	if r := eps.call(t, node, http.MethodGet, "/v1/secrets/gh-admin", nil); r.code != 200 || r.body != "ghp-admin" {
		t.Fatalf("within access: %d %q", r.code, r.body)
	}

	// 4. Signing: dee can't approve the key (no danger=high label), ada can deny it.
	pk := eps.call(t, node, http.MethodGet, "/v1/keys/deploy-key", nil)
	if pk.code != 200 {
		t.Fatalf("public key needs no yes: %d %s", pk.code, pk.body)
	}
	sign := func() {
		got <- eps.ask(t, ctx, node, http.MethodPost, "/v1/sign/deploy-key", []byte("release v1"), 20*time.Millisecond, nil)
	}
	go sign()
	s := pendingOf(v1.ApprovalForSign, "deploy-key")
	if !strings.Contains(s.Spec.Summary, "sign 10 bytes") || len(s.Spec.PayloadHash) != 64 {
		t.Fatalf("sign approval: %+v", s.Spec)
	}
	if err := answer(dee, s.Name, "approve", ""); status(err) != http.StatusForbidden {
		t.Fatalf("dee approved a key outside her label: %v", err)
	}
	if err := answer(ada, s.Name, "deny", "not before the freeze ends"); err != nil {
		t.Fatal(err)
	}
	if r := <-got; r.code != 403 || !strings.Contains(r.msg(), "denied by ada: not before the freeze ends") {
		t.Fatalf("after deny: %+v", r)
	}
	// Asking again is a new request; approved, the signature verifies.
	go sign()
	s = pendingOf(v1.ApprovalForSign, "deploy-key")
	if err := answer(ada, s.Name, "approve", ""); err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(strings.TrimSpace(pk.body))
	r = <-got
	sig, _ := hex.DecodeString(strings.TrimSpace(r.body))
	if r.code != 200 || !ed25519.Verify(pub, []byte("release v1"), sig) {
		t.Fatalf("approved sign: %d %s", r.code, r.body)
	}

	// 5. Nobody answers: the request expires and the call says so; a late answer is refused.
	// (Access to gh-admin is still active, so use a new silo of its own.)
	late := silo("late", "web3")
	late.Spec.Grants = []string{"dangerous"}
	_ = c.admin.Create(c.ctx, late)
	late.Status.Host = "hv1"
	_ = c.admin.UpdateStatus(c.ctx, late)
	eps.add(t, late)
	if r := eps.ask(t, ctx, late, http.MethodGet, "/v1/secrets/gh-admin?wait=1s", nil, 100*time.Millisecond, nil); r.code != 403 || !strings.Contains(r.msg(), "expired") {
		t.Fatalf("unanswered: %d %s", r.code, r.body)
	}
	var expired *v1.Approval
	l, _ := ada.List(c.ctx, "Approval", "web3")
	for _, raw := range l.Items {
		obj, _, _ := v1.Decode(raw)
		if x := obj.(*v1.Approval); x.Spec.Silo == "late" {
			expired = x
		}
	}
	if expired == nil || expired.Status.Phase != v1.ApprovalExpired {
		t.Fatalf("late's approval: %+v", expired)
	}
	if err := answer(ada, expired.Name, "approve", ""); status(err) != http.StatusConflict {
		t.Fatalf("answer after expiry: %v", err)
	}
	// Limits: more access than the cluster allows is refused up front.
	if r := eps.call(t, late, http.MethodGet, "/v1/secrets/gh-admin?for=100h", nil); r.code != 403 || !strings.Contains(r.msg(), "more than this cluster allows") {
		t.Fatalf("too long: %d %s", r.code, r.body)
	}

	// 6. The audit log has each request and answer, with who answered.
	var asked, approvedBy, deniedBy bool
	for _, e := range c.audit.Entries() {
		switch {
		case e.Event == "approval-requested" && e.User == "system:silo:web3:agent":
			asked = true
		case e.Event == "approval-Approved" && e.User == "dee":
			approvedBy = true
		case e.Event == "approval-Denied" && e.User == "ada":
			deniedBy = true
		}
	}
	if !asked || !approvedBy || !deniedBy {
		t.Fatalf("audit: asked %v, approved %v, denied %v", asked, approvedBy, deniedBy)
	}
}
