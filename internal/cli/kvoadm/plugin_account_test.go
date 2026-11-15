package kvoadm

import (
	"context"
	"net/http/httptest"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/names"
	"kevaso.com/core/internal/store"
)

// kevaso-system is an ordinary namespace: not a network name, and creating it binds nobody.
// Install creates the service account when it is missing and leaves it when it is there.
// It does not create a role or a binding. Removing the account leaves the namespace, and
// a second plugin's account.
func TestPluginServiceAccount(t *testing.T) {
	if names.Reserved(v1.PluginNamespace) {
		t.Fatal("kevaso-system is a network name (mesh, internal, external): install could not create it")
	}
	if err := meta.ValidateName(v1.PluginNamespace); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)

	if pluginAccountBindLine("juicefs") != "bind a ClusterRole to service account plugin-juicefs in namespace kevaso-system" {
		t.Fatalf("bind line: %s", pluginAccountBindLine("juicefs"))
	}
	if err := ensurePluginServiceAccount(ctx, c, "juicefs"); err != nil {
		t.Fatal(err)
	}
	var ns v1.Namespace
	if err := c.Get(ctx, "Namespace", "", v1.PluginNamespace, &ns); err != nil {
		t.Fatal(err)
	}
	var sa v1.ServiceAccount
	if err := c.Get(ctx, "ServiceAccount", v1.PluginNamespace, "plugin-juicefs", &sa); err != nil {
		t.Fatal(err)
	}
	uid, rv := sa.UID, sa.ResourceVersion
	nsRV := ns.ResourceVersion
	if err := ensurePluginServiceAccount(ctx, c, "juicefs"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "ServiceAccount", v1.PluginNamespace, "plugin-juicefs", &sa); err != nil || sa.UID != uid || sa.ResourceVersion != rv {
		t.Fatalf("a second install changed the account: uid %s rv %s, was %s %s (%v)", sa.UID, sa.ResourceVersion, uid, rv, err)
	}
	if err := c.Get(ctx, "Namespace", "", v1.PluginNamespace, &ns); err != nil || ns.ResourceVersion != nsRV {
		t.Fatalf("a second install changed the namespace: %s %v", ns.ResourceVersion, err)
	}
	if err := ensurePluginServiceAccount(ctx, c, "linode"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"RoleBinding", "Role"} {
		l, err := c.List(ctx, kind, v1.PluginNamespace)
		if err != nil || len(l.Items) != 0 {
			n := 0
			if l != nil {
				n = len(l.Items)
			}
			t.Fatalf("install put a %s in %s (%d): %v", kind, v1.PluginNamespace, n, err)
		}
	}
	for _, kind := range []string{"ClusterRole", "ClusterRoleBinding"} {
		l, err := c.List(ctx, kind, "")
		if err != nil || len(l.Items) != 0 {
			n := 0
			if l != nil {
				n = len(l.Items)
			}
			t.Fatalf("install created a %s (%d): %v", kind, n, err)
		}
	}

	if err := deletePluginServiceAccount(ctx, c, "juicefs"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "ServiceAccount", v1.PluginNamespace, "plugin-juicefs", &sa); !client.IsNotFound(err) {
		t.Fatalf("plugin-juicefs still there: %v", err)
	}
	if err := c.Get(ctx, "ServiceAccount", v1.PluginNamespace, "plugin-linode", &v1.ServiceAccount{}); err != nil {
		t.Fatalf("plugin-linode was removed with juicefs: %v", err)
	}
	if err := c.Get(ctx, "Namespace", "", v1.PluginNamespace, &ns); err != nil {
		t.Fatalf("the namespace was removed: %v", err)
	}
	if err := deletePluginServiceAccount(ctx, c, "juicefs"); err != nil {
		t.Fatalf("deleting an account that is already gone: %v", err)
	}
	if err := ensurePluginServiceAccount(ctx, c, "juicefs"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "ServiceAccount", v1.PluginNamespace, "plugin-juicefs", &sa); err != nil || sa.UID == uid {
		t.Fatalf("the account was not created again: %+v %v", sa, err)
	}
}
