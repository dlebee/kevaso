package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// K-128: deleting a namespace is refused while any object outside it still names it, the same
// 409 as while it holds objects, listing them (count per kind, the first three as namespace/name)
// and saying to remove those first. A create or an update that newly names a namespace being
// deleted is refused too, including one whose check ran before the namespace was marked.
func TestANamespaceStillNamedFromOutsideIsNotDeleted(t *testing.T) {
	t.Run("each kind", testEachOutsideNameBlocksNamespaceDelete)
	t.Run("the first three", testOutsideNamesListTheFirstThree)
	t.Run("while it is being deleted", testCreateNamingATerminatingNamespaceIsRefused)
	t.Run("checked before the mark", testCreateNamingANamespaceDeletedDuringTheWriteIsRefused)
}

func testEachOutsideNameBlocksNamespaceDelete(t *testing.T) {
	e := setupAuth(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must(e.admin.Create(e.ctx, ns("web3")))
	must(e.admin.Create(e.ctx, ns("shop")))

	// These do not name web3. A user subject's namespace is not part of who the binding is for,
	// an allowFrom without a slash is a silo in the same namespace, and a grant, a service and an
	// ingress name things in their own namespace. A policy that lists no namespaces matches every
	// one without naming one. None of them keeps web3 from being deleted.
	must(e.admin.Create(e.ctx, roleBind(tm, "shop", "users", v1.Subject{Kind: "User", Name: "ci", Namespace: "web3"})))
	must(e.admin.Create(e.ctx, roleBind(tm, "shop", "local", v1.Subject{Kind: "ServiceAccount", Name: "ci"})))
	must(e.admin.Create(e.ctx, siloAllow(tm, "local", "buddy", "ops/ci")))
	must(e.admin.Create(e.ctx, &v1.Grant{TypeMeta: tm("Grant"), ObjectMeta: meta.ObjectMeta{Name: "out", Namespace: "shop"},
		Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "example.com"}}}}))
	must(e.admin.Create(e.ctx, &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "front", Namespace: "shop"},
		Spec: v1.ServiceSpec{Selector: map[string]string{"app": "front"}, Ports: []v1.ServicePortSpec{{Name: "http", Port: 80}}}}))
	// The class names shop, where its controller would live, not web3.
	must(e.admin.Create(e.ctx, &v1.IngressClass{TypeMeta: tm("IngressClass"), ObjectMeta: meta.ObjectMeta{Name: "office"},
		Spec: v1.IngressClassSpec{Controller: v1.IngressController{Driver: "nginx", Namespace: "shop", Silo: "edge"}}}))
	must(e.admin.Create(e.ctx, &v1.Ingress{TypeMeta: tm("Ingress"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "shop"},
		Spec: v1.IngressSpec{IngressClass: "office", Hosts: []string{"shop.example.com"},
			Rules: []v1.IngressRule{{Service: v1.IngressTarget{Name: "front", Port: "http"}}}}}))
	must(e.admin.Create(e.ctx, policy(tm, "everywhere", nil)))
	if err := e.admin.Delete(e.ctx, "Namespace", "", "web3"); err != nil {
		t.Fatalf("deleting web3 while nothing outside names it: %v", err)
	}
	must(e.admin.Create(e.ctx, ns("web3")))

	sa := v1.Subject{Kind: "ServiceAccount", Name: "ci", Namespace: "web3"}
	cases := []struct {
		kind, namespace, name, want string
		obj                         meta.Object
	}{
		{"RoleBinding", "shop", "to-ci", "1 RoleBinding (shop/to-ci)", roleBind(tm, "shop", "to-ci", sa)},
		{"ClusterRoleBinding", "", "to-ci", "1 ClusterRoleBinding (to-ci)", &v1.ClusterRoleBinding{
			TypeMeta: tm("ClusterRoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "to-ci"},
			RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "viewer"}, Subjects: []v1.Subject{sa}}},
		{"Silo", "shop", "api", "1 Silo (shop/api)", siloAllow(tm, "api", "web3/ci")},
		{"SiloSet", "shop", "edge", "1 SiloSet (shop/edge)", &v1.SiloSet{
			TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "edge", Namespace: "shop"},
			Spec: v1.SiloSetSpec{Instances: 1, Template: v1.SiloTemplate{SiloSpec: siloAllow(tm, "edge", "web3/ci").Spec}}}},
		{"IngressClass", "", "public", "1 IngressClass (public)", &v1.IngressClass{
			TypeMeta: tm("IngressClass"), ObjectMeta: meta.ObjectMeta{Name: "public"},
			Spec: v1.IngressClassSpec{Controller: v1.IngressController{Driver: "nginx", Namespace: "web3", Silo: "edge"}}}},
		{"Plugin", "", "demo", "1 Plugin (demo)", &v1.Plugin{
			TypeMeta: tm("Plugin"), ObjectMeta: meta.ObjectMeta{Name: "demo"},
			Spec: v1.PluginSpec{Version: "1", Owns: []v1.PluginObject{{Kind: "ServiceAccount", Namespace: "web3", Name: "ci"}}}}},
		{"ValidationPolicy", "", "on-web3", "1 ValidationPolicy (on-web3)", policy(tm, "on-web3", []string{"web3"})},
		{"MutationPolicy", "", "on-web3", "1 MutationPolicy (on-web3)", &v1.MutationPolicy{
			TypeMeta: tm("MutationPolicy"), ObjectMeta: meta.ObjectMeta{Name: "on-web3"},
			Spec: v1.MutationPolicySpec{Match: v1.PolicyMatch{Kinds: []string{"Silo"}, Namespaces: []string{"web3"}},
				Mutations: []v1.Mutation{{Field: "metadata.labels.kept", Value: "'yes'"}}}}},
	}
	for _, tc := range cases {
		must(e.admin.Create(e.ctx, tc.obj))
		err := e.admin.Delete(e.ctx, "Namespace", "", "web3")
		if code(err) != http.StatusConflict {
			t.Fatalf("deleting web3 while %s %s names it: %v, want 409", tc.kind, tc.name, err)
		}
		msg := err.(*client.Error).Message
		if !strings.Contains(msg, "named from outside by "+tc.want+":") || !strings.Contains(msg, "remove those first") {
			t.Fatalf("refusal %q, want it to name %q and say to remove those first", msg, tc.want)
		}
		var n v1.Namespace
		if err := e.admin.Get(e.ctx, "Namespace", "", "web3", &n); err != nil {
			t.Fatalf("web3 is gone: %v", err)
		}
		if n.Status.Phase != "Active" {
			t.Fatalf("web3 phase %q after the refusal, want Active", n.Status.Phase)
		}
		must(e.admin.Delete(e.ctx, tc.kind, tc.namespace, tc.name))
	}
	if err := e.admin.Delete(e.ctx, "Namespace", "", "web3"); err != nil {
		t.Fatalf("deleting web3 once nothing outside names it: %v", err)
	}

	// The binding has to be gone before the delete, so creating web3 again does not find it.
	must(e.admin.Create(e.ctx, ns("web3")))
	must(e.admin.Create(e.ctx, roleBind(tm, "shop", "inherit", sa)))
	err := e.admin.Delete(e.ctx, "Namespace", "", "web3")
	if code(err) != http.StatusConflict || !strings.Contains(err.Error(), "1 RoleBinding (shop/inherit)") {
		t.Fatalf("deleting web3 while shop/inherit names it: %v, want 409 naming it", err)
	}
	if err := e.admin.Get(e.ctx, "RoleBinding", "shop", "inherit", &v1.RoleBinding{}); err != nil {
		t.Fatalf("the binding was removed with the namespace: %v", err)
	}
	must(e.admin.Delete(e.ctx, "RoleBinding", "shop", "inherit"))
	must(e.admin.Delete(e.ctx, "Namespace", "", "web3"))
	must(e.admin.Create(e.ctx, ns("web3")))
	must(e.admin.Create(e.ctx, &v1.ServiceAccount{TypeMeta: tm("ServiceAccount"), ObjectMeta: meta.ObjectMeta{Name: "ci", Namespace: "web3"}}))
	if err := e.admin.Get(e.ctx, "RoleBinding", "shop", "inherit", &v1.RoleBinding{}); !client.IsNotFound(err) {
		t.Fatalf("shop/inherit is still there after web3 was deleted and created again: %v", err)
	}
}

func testOutsideNamesListTheFirstThree(t *testing.T) {
	e := setupAuth(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must(e.admin.Create(e.ctx, ns("web3")))
	must(e.admin.Create(e.ctx, ns("shop")))
	sa := v1.Subject{Kind: "ServiceAccount", Name: "ci", Namespace: "web3"}
	for _, name := range []string{"a", "b", "c", "d"} {
		must(e.admin.Create(e.ctx, roleBind(tm, "shop", name, sa)))
	}
	err := e.admin.Delete(e.ctx, "Namespace", "", "web3")
	if code(err) != http.StatusConflict {
		t.Fatalf("deleting web3: %v, want 409", err)
	}
	msg := err.(*client.Error).Message
	want := "4 RoleBinding (shop/a, shop/b, shop/c, …)"
	if !strings.Contains(msg, want) || strings.Contains(msg, "shop/d") {
		t.Fatalf("refusal %q, want %q and not the fourth", msg, want)
	}
	for _, name := range []string{"a", "b", "c", "d"} {
		must(e.admin.Delete(e.ctx, "RoleBinding", "shop", name))
	}
	if err := e.admin.Delete(e.ctx, "Namespace", "", "web3"); err != nil {
		t.Fatalf("deleting web3 once the bindings are gone: %v", err)
	}
}

// countStore counts creates and can run a hook from inside one store call.
type countStore struct {
	store.Store
	mu           sync.Mutex
	keys         []store.Key
	afterList    func(store.Selector) bool
	beforeCreate func(store.Key) bool
}

func (s *countStore) List(ctx context.Context, sel store.Selector) ([]store.Object, int64, error) {
	objs, rev, err := s.Store.List(ctx, sel)
	s.mu.Lock()
	f := s.afterList
	s.mu.Unlock()
	if f != nil && f(sel) {
		s.mu.Lock()
		s.afterList = nil
		s.mu.Unlock()
	}
	return objs, rev, err
}

func (s *countStore) Create(ctx context.Context, k store.Key, data []byte) (store.Object, error) {
	s.mu.Lock()
	f := s.beforeCreate
	s.mu.Unlock()
	if f != nil && f(k) {
		s.mu.Lock()
		s.beforeCreate = nil
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.keys = append(s.keys, k)
	s.mu.Unlock()
	return s.Store.Create(ctx, k, data)
}

func (s *countStore) created(kind, namespace, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.Kind == kind && k.Namespace == namespace && k.Name == name {
			return true
		}
	}
	return false
}

func serveStore(t *testing.T, st store.Store) (*client.Client, context.Context) {
	t.Helper()
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return client.New(ts.URL), ctx
}

func testCreateNamingATerminatingNamespaceIsRefused(t *testing.T) {
	st := &countStore{Store: store.NewMemory(0)}
	c, ctx := serveStore(t, st)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, ns("web3")))
	must(c.Create(ctx, ns("shop")))
	extra := roleBind(tm, "shop", "extra", v1.Subject{Kind: "User", Name: "ada"})
	must(c.Create(ctx, extra))

	var created, updated error
	st.mu.Lock()
	st.afterList = func(sel store.Selector) bool {
		if sel.Kind != "RoleBinding" || sel.Namespace != "web3" {
			return false
		}
		created = c.Create(ctx, roleBind(tm, "shop", "during", v1.Subject{Kind: "ServiceAccount", Name: "ci", Namespace: "web3"}))
		extra.Subjects = append(extra.Subjects, v1.Subject{Kind: "ServiceAccount", Name: "ci", Namespace: "web3"})
		updated = c.Update(ctx, extra)
		return true
	}
	st.mu.Unlock()
	if err := c.Delete(ctx, "Namespace", "", "web3"); err != nil {
		t.Fatalf("deleting web3: %v", err)
	}
	if code(created) != http.StatusConflict || !strings.Contains(created.Error(), "nothing new can name it") {
		t.Fatalf("creating a binding that names web3 while it is being deleted: %v, want 409", created)
	}
	if code(updated) != http.StatusConflict || !strings.Contains(updated.Error(), "nothing new can name it") {
		t.Fatalf("adding a subject in web3 while it is being deleted: %v, want 409", updated)
	}
	if st.created("RoleBinding", "shop", "during") {
		t.Fatal("the refused binding was written")
	}
	if err := c.Get(ctx, "RoleBinding", "shop", "during", &v1.RoleBinding{}); !client.IsNotFound(err) {
		t.Fatalf("the refused binding is stored: %v", err)
	}
	var got v1.RoleBinding
	if err := c.Get(ctx, "RoleBinding", "shop", "extra", &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Subjects) != 1 || got.Subjects[0].Kind != "User" {
		t.Fatalf("shop/extra subjects are %v, want the user it had", got.Subjects)
	}
	if err := c.Get(ctx, "Namespace", "", "web3", &v1.Namespace{}); !client.IsNotFound(err) {
		t.Fatalf("web3 was kept: %v", err)
	}
}

func testCreateNamingANamespaceDeletedDuringTheWriteIsRefused(t *testing.T) {
	st := &countStore{Store: store.NewMemory(0)}
	c, ctx := serveStore(t, st)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, ns("web3")))
	must(c.Create(ctx, ns("shop")))

	var deleted error
	st.mu.Lock()
	st.beforeCreate = func(k store.Key) bool {
		if k.Kind != "RoleBinding" || k.Name != "racing" {
			return false
		}
		deleted = c.Delete(ctx, "Namespace", "", "web3")
		return true
	}
	st.mu.Unlock()
	created := c.Create(ctx, roleBind(tm, "shop", "racing", v1.Subject{Kind: "ServiceAccount", Name: "ci", Namespace: "web3"}))
	if deleted != nil {
		t.Fatalf("deleting empty web3: %v", deleted)
	}
	if code(created) != http.StatusConflict || !strings.Contains(created.Error(), "nothing new can name it") {
		t.Fatalf("binding create: %v, want 409 because web3 was deleted during the write", created)
	}
	if err := c.Get(ctx, "RoleBinding", "shop", "racing", &v1.RoleBinding{}); !client.IsNotFound(err) {
		t.Fatalf("the binding was kept: %v", err)
	}
	if err := c.Get(ctx, "Namespace", "", "web3", &v1.Namespace{}); !client.IsNotFound(err) {
		t.Fatalf("web3 was kept: %v", err)
	}
}

func roleBind(tm func(string) meta.TypeMeta, namespace, name string, subs ...v1.Subject) *v1.RoleBinding {
	return &v1.RoleBinding{TypeMeta: tm("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "viewer"}, Subjects: subs}
}

func siloAllow(tm func(string) meta.TypeMeta, name string, from ...string) *v1.Silo {
	return &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "shop"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Ports: []v1.SiloPort{{Name: "http", Port: 8080}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", AllowFrom: from}}}}}
}

func policy(tm func(string) meta.TypeMeta, name string, namespaces []string) *v1.ValidationPolicy {
	return &v1.ValidationPolicy{TypeMeta: tm("ValidationPolicy"), ObjectMeta: meta.ObjectMeta{Name: name},
		Spec: v1.ValidationPolicySpec{Match: v1.PolicyMatch{Kinds: []string{"Silo"}, Namespaces: namespaces},
			Validations: []v1.PolicyValidation{{Expression: "true", Message: "ok"}}}}
}
