package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/guest"
	"kevaso.com/core/sdk/kri"
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
	dir, _ := os.MkdirTemp("/tmp", "kva")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ch := channels{dir}
	hv1Client := c.host(t, "hv1")
	hv1 := &agent.Broker{Client: hv1Client}
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	if err := hv1.Ensure(ctx, ch, kri.ID{Namespace: "web3", Name: "agent", UID: node.UID}); err != nil {
		t.Fatal(err)
	}
	dial := ch.dialer(node.UID)

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
	if r, err := guest.Call(ctx, dial, client.BrokerRequest{Op: client.OpGetSecret, Name: "db-password"}); err != nil || string(r.Value) != "pw" {
		t.Fatalf("ungated secret: %q %v", r.Value, err)
	}

	// 1. The silo asks for gh-admin: the call waits.
	type result struct {
		resp client.BrokerResponse
		err  error
	}
	got := make(chan result, 1)
	var waitedOn client.ApprovalWait
	go func() {
		r, err := guest.Ask(ctx, dial, client.BrokerRequest{Op: client.OpGetSecret, Name: "gh-admin", For: "20m"}, 20*time.Millisecond,
			func(a client.ApprovalWait) { waitedOn = a })
		got <- result{r, err}
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
	if r.err != nil || string(r.resp.Value) != "ghp-admin" || waitedOn.Name != a.Name {
		t.Fatalf("after approval: %q %v (waited on %q)", r.resp.Value, r.err, waitedOn.Name)
	}
	if err := answer(ada, a.Name, "deny", ""); status(err) != http.StatusConflict {
		t.Fatalf("second answer: %v", err)
	}
	// While access lasts, the silo doesn't ask again.
	if r, err := guest.Call(ctx, dial, client.BrokerRequest{Op: client.OpGetSecret, Name: "gh-admin"}); err != nil || string(r.Value) != "ghp-admin" || r.Pending != nil {
		t.Fatalf("within access: %+v %v", r, err)
	}

	// 4. Signing: dee can't approve the key (no danger=high label), ada can deny it.
	pk, err := guest.Call(ctx, dial, client.BrokerRequest{Op: client.OpPublicKey, Name: "deploy-key"})
	if err != nil {
		t.Fatalf("public key needs no yes: %v", err)
	}
	go func() {
		r, err := guest.Ask(ctx, dial, client.BrokerRequest{Op: client.OpSign, Name: "deploy-key", Payload: []byte("release v1")}, 20*time.Millisecond, nil)
		got <- result{r, err}
	}()
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
	if r := <-got; r.err == nil || !strings.Contains(r.err.Error(), "denied by ada: not before the freeze ends") {
		t.Fatalf("after deny: %+v", r)
	}
	// Asking again is a new request; approved, the signature verifies.
	go func() {
		r, err := guest.Ask(ctx, dial, client.BrokerRequest{Op: client.OpSign, Name: "deploy-key", Payload: []byte("release v1")}, 20*time.Millisecond, nil)
		got <- result{r, err}
	}()
	s = pendingOf(v1.ApprovalForSign, "deploy-key")
	if err := answer(ada, s.Name, "approve", ""); err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(pk.PublicKey)
	if r := <-got; r.err != nil || !ed25519.Verify(pub, []byte("release v1"), r.resp.Signature) {
		t.Fatalf("approved sign: %v", r.err)
	}

	// 5. Nobody answers: the request expires and the call says so; a late answer is refused.
	// (Access to gh-admin is still active, so use a new silo of its own.)
	late := silo("late", "web3")
	late.Spec.Grants = []string{"dangerous"}
	_ = c.admin.Create(c.ctx, late)
	late.Status.Host = "hv1"
	_ = c.admin.UpdateStatus(c.ctx, late)
	if err := hv1.Ensure(ctx, ch, kri.ID{Namespace: "web3", Name: "late", UID: late.UID}); err != nil {
		t.Fatal(err)
	}
	_, err = guest.Ask(ctx, ch.dialer(late.UID), client.BrokerRequest{Op: client.OpGetSecret, Name: "gh-admin", Wait: "1s"}, 100*time.Millisecond, nil)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("unanswered: %v", err)
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
	if _, err := guest.Call(ctx, ch.dialer(late.UID), client.BrokerRequest{Op: client.OpGetSecret, Name: "gh-admin", For: "100h"}); err == nil || !strings.Contains(err.Error(), "more than this cluster allows") {
		t.Fatalf("too long: %v", err)
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
