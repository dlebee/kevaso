package integration

import (
	"net/http"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/operators"
)

// A plugin's service account renews its own token in kevaso-system. Any other write there by
// that account is still refused, including one its roles would otherwise allow.
func TestPluginRenewsItsOwnToken(t *testing.T) {
	c := newCluster(t)
	sys := v1.PluginNamespace
	own := operators.ServiceAccountName("sessions")
	if err := c.admin.Create(c.ctx, ns(sys)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{own, "other"} {
		if err := c.admin.Create(c.ctx, &v1.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ServiceAccount"},
			ObjectMeta: meta.ObjectMeta{Name: name, Namespace: sys}}); err != nil {
			t.Fatal(err)
		}
	}
	self := &v1.Role{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Role"},
		ObjectMeta: meta.ObjectMeta{Name: own + "-self", Namespace: sys},
		Rules:      []v1.PolicyRule{{Verbs: []string{"create"}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{own}}}}
	wide := &v1.Role{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Role"},
		ObjectMeta: meta.ObjectMeta{Name: own + "-wide", Namespace: sys},
		Rules: []v1.PolicyRule{
			{Verbs: []string{"create"}, Resources: []string{"secrets"}},
			{Verbs: []string{"create"}, Resources: []string{"serviceaccounts/token"}},
			{Verbs: []string{"update"}, Resources: []string{"serviceaccounts"}},
		}}
	for _, role := range []*v1.Role{self, wide} {
		if err := c.admin.Create(c.ctx, role); err != nil {
			t.Fatal(err)
		}
		if err := c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
			ObjectMeta: meta.ObjectMeta{Name: role.Name, Namespace: sys},
			RoleRef:    v1.RoleRef{Kind: "Role", Name: role.Name},
			Subjects:   []v1.Subject{{Kind: "ServiceAccount", Name: own, Namespace: sys}}}); err != nil {
			t.Fatal(err)
		}
	}
	as, done := c.asServiceAccount(t, sys, own)
	defer done()

	path, err := client.Path("ServiceAccount", sys, own)
	if err != nil {
		t.Fatal(err)
	}
	var resp client.TokenResponse
	if err := as.Call(c.ctx, http.MethodPost, path+"/token", client.TokenRequest{Duration: time.Hour.String()}, &resp); err != nil || resp.Token == "" {
		t.Fatalf("renewing its own token: %v", err)
	}
	other, err := client.Path("ServiceAccount", sys, "other")
	if err != nil {
		t.Fatal(err)
	}
	wantReserved(t, as.Call(c.ctx, http.MethodPost, other+"/token", client.TokenRequest{Duration: time.Hour.String()}, &resp), "a token for another account")
	wantReserved(t, as.Create(c.ctx, &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: "extra", Namespace: sys}}), "a secret in "+sys)
	var got v1.ServiceAccount
	if err := c.admin.Get(c.ctx, "ServiceAccount", sys, own, &got); err != nil {
		t.Fatal(err)
	}
	wantReserved(t, as.Update(c.ctx, &got), "updating its own service account")
}
