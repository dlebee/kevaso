package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/approvals"
	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/store"
)

// K-059 through the API and kvo: two requests of one silo ("1 minute" and "12 hours") whose old
// 48-bit IDs agree. A person reads the first; the silo asks again with the second; no short form
// is a yes, and what kvo sends for a typed prefix is the full digest of the request as it is.
func TestApprovalIsBoundToTheFullDigest(t *testing.T) {
	c := newCluster(t)
	home := t.TempDir()
	cfgPath := filepath.Join(home, "config.yaml")
	t.Setenv("KVO_CONFIG", cfgPath)
	t.Setenv("KVO_TOKEN_STORE", "file")
	t.Setenv("KVO_SERVER", "")
	_ = c.admin.Create(c.ctx, ns("web3"))
	if err := c.admin.Create(c.ctx, secretObj("key", nil, "k")); err != nil {
		t.Fatal(err)
	}
	key, csr, _ := clientKeyCSR(t)
	cert, ca, err := c.admin.SignUserCSR(c.ctx, "david", csr)
	if err != nil {
		t.Fatal(err)
	}
	if err := kvoconfig.AddContext(cfgPath, "admin", c.url, ca, cert, key); err != nil {
		t.Fatal(err)
	}
	c.bind(t, "ada", "ClusterRole", "admin")
	ada := c.as(t, "ada")

	ask := func(forv string, payload int) *v1.Approval {
		call := approvals.Call{Namespace: "web3", Silo: "s", SiloUID: "u1", Secret: "key", Use: v1.ApprovalForSign, Grant: "g",
			For: forv, PayloadHash: fmt.Sprintf("%016x", payload), Summary: "sign 32 bytes"}
		a := approvals.Decide(call, nil, approvals.Limits{}, time.Now()).Store
		a.UID, a.ResourceVersion = "approval-uid", ""
		now := time.Now().UTC().Truncate(time.Second)
		a.CreationTimestamp, a.Generation = &now, 1
		return a
	}
	first, second := ask("1m", 0x12a00be), ask("12h", 0xd1d704)
	idFirst, idSecond := approvals.RequestID(first), approvals.RequestID(second)
	if first.Name != second.Name || idFirst == idSecond || idFirst[:12] != idSecond[:12] {
		t.Fatalf("the pair: names %s/%s, 48-bit forms %s/%s", first.Name, second.Name, idFirst[:12], idSecond[:12])
	}
	key0 := store.Key{Kind: "Approval", Namespace: "web3", Name: first.Name}
	put := func(a *v1.Approval, rev int64) int64 {
		t.Helper()
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		var o store.Object
		if rev == 0 {
			o, err = c.store.Create(c.ctx, key0, data)
		} else {
			o, err = c.store.Update(c.ctx, key0, data, rev)
		}
		if err != nil {
			t.Fatal(err)
		}
		return o.Revision
	}
	rev := put(first, 0)
	// The silo asks again with the 12-hour request: it replaces the pending one.
	put(second, rev)

	path := "/apis/kevaso/v1/namespaces/web3/approvals/" + first.Name + "/approve"
	answer := func(request string) error {
		return ada.Call(c.ctx, http.MethodPost, path, client.ApprovalAnswer{Request: request}, nil)
	}
	for name, req := range map[string]string{"the 48-bit form": idFirst[:12], "a prefix of the current one": idSecond[:40], "the first request's digest": idFirst} {
		if err := answer(req); err == nil {
			t.Errorf("%s was accepted over the API", name)
		}
	}
	if err := answer(idFirst[:12]); status(err) != http.StatusBadRequest {
		t.Errorf("a short form: %v, want 400", err)
	}
	if err := answer(idFirst); status(err) != http.StatusConflict {
		t.Errorf("another request's digest: %v, want 409", err)
	}
	var now v1.Approval
	if err := c.admin.Get(c.ctx, "Approval", "web3", first.Name, &now); err != nil || now.Status.Phase != v1.ApprovalPending {
		t.Fatalf("after the refusals: %v %s, want still pending", err, now.Status.Phase)
	}

	// kvo: what the person read (the shown form of the first request) is not the second; too short a
	// prefix is refused; the shown form of the current request is completed to its full digest.
	kvoApprove := func(request string) (string, string, int) {
		return run(c.ctx, kvoCmd, "", "approve", first.Name, "-n", "web3", "--request", request, "--context", "admin")
	}
	for name, req := range map[string]string{"read before it changed": approvals.ShortID(idFirst), "48 bits": idFirst[:12], "a prefix too short": idSecond[:approvals.MinPrefix-1], "not hex": strings.Repeat("g", 40)} {
		if out, errs, code := kvoApprove(req); code == 0 {
			t.Errorf("kvo approve --request (%s): exit 0\n%s%s", name, out, errs)
		}
	}
	if err := c.admin.Get(c.ctx, "Approval", "web3", first.Name, &now); err != nil || now.Status.Phase != v1.ApprovalPending {
		t.Fatalf("after kvo's refusals: %v %s, want still pending", err, now.Status.Phase)
	}
	if out, errs, code := kvoApprove(approvals.ShortID(idSecond)); code != 0 {
		t.Fatalf("kvo approve with the shown form: exit %d\n%s%s", code, out, errs)
	}
	if err := c.admin.Get(c.ctx, "Approval", "web3", first.Name, &now); err != nil || now.Status.Phase != v1.ApprovalApproved || now.Spec.For != "12h0m0s" {
		t.Fatalf("after the right yes: %v %s for %s", err, now.Status.Phase, now.Spec.For)
	}
}
