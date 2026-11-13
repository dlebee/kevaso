package integration

import (
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// The built-in guards run on the object as stored, after mutation policies (ADR 0005 §9a): for
// each one, a mutation policy tries to hand a write what the guard stands for, and can't.
func TestMutationPoliciesCantGetPastGuards(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	c.bind(t, "ed", "ClusterRole", "editor")
	c.bind(t, "ada", "ClusterRole", "admin")
	// dev writes silos and grants but may use no secret (editors may use them all).
	if err := c.admin.Create(c.ctx, &v1.Role{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Role"},
		ObjectMeta: meta.ObjectMeta{Name: "no-secrets", Namespace: "web3"}, Rules: []v1.PolicyRule{
			{Verbs: []string{"get", "list", "watch", "create", "update", "delete"}, Resources: []string{"grants", "silos"}}}}); err != nil {
		t.Fatal(err)
	}
	c.bind(t, "dev", "Role", "no-secrets")
	ed, ada, dev := c.as(t, "ed"), c.as(t, "ada"), c.as(t, "dev")
	if err := c.admin.Create(c.ctx, &v1.IngressClass{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IngressClass"},
		ObjectMeta: meta.ObjectMeta{Name: "public"}, Spec: v1.IngressClassSpec{Public: true, Controller: v1.IngressController{Driver: "nginx", Silo: "edge", Namespace: "web3"}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.IngressClass{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IngressClass"},
		ObjectMeta: meta.ObjectMeta{Name: "office"}, Spec: v1.IngressClassSpec{Controller: v1.IngressController{Driver: "nginx", Silo: "edge", Namespace: "web3"}}}); err != nil {
		t.Fatal(err)
	}
	// A secret ed may not use, and a grant naming it.
	if err := ada.Create(c.ctx, secretObj("root-key", nil, "root-value")); err != nil {
		t.Fatal(err)
	}
	if err := ada.Create(c.ctx, grantObj("root", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "root-key"}}})); err != nil {
		t.Fatal(err)
	}
	if err := dev.Create(c.ctx, grantObj("none", v1.GrantSpec{Egress: []v1.EgressRule{{To: "api.github.com"}}})); err != nil {
		t.Fatalf("editor, a grant without secrets: %v", err)
	}

	policy := func(t *testing.T, kind, field, value string) {
		t.Helper()
		p := &v1.MutationPolicy{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "MutationPolicy"}, ObjectMeta: meta.ObjectMeta{Name: "sneaky"},
			Spec: v1.MutationPolicySpec{Match: v1.PolicyMatch{Kinds: []string{kind}}, Mutations: []v1.Mutation{{Field: field, Value: value}}}}
		if err := c.admin.Create(c.ctx, p); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.admin.Delete(c.ctx, "MutationPolicy", "", "sneaky") })
	}
	want := func(t *testing.T, what string, err error, code int, msg string) {
		t.Helper()
		if status(err) != code || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: %v, want %d %q", what, err, code, msg)
		}
	}
	ingress := func(name, class string) *v1.Ingress {
		return &v1.Ingress{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Ingress"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3"},
			Spec: v1.IngressSpec{IngressClass: class, Hosts: []string{"api.example.com"}, Rules: []v1.IngressRule{{Path: "/", Silo: v1.IngressTarget{Name: "api", Port: "http"}}}}}
	}

	t.Run("exposure", func(t *testing.T) {
		policy(t, "Silo", "spec.service", `{'ports': [{'name': 'p2p', 'port': 30303}], 'expose': 'hostPort'}`)
		want(t, "editor", ed.Create(c.ctx, silo("e1", "web3")), http.StatusForbidden, "services/expose-public")
		want(t, "admin socket", c.admin.Create(c.ctx, silo("e2", "web3")), http.StatusForbidden, "policies can't grant privileges")
		if err := ada.Create(c.ctx, silo("e3", "web3")); err != nil {
			t.Errorf("admin, who may expose: %v", err)
		}
	})
	t.Run("publish-public", func(t *testing.T) {
		policy(t, "Ingress", "spec.ingressClass", `'public'`)
		want(t, "editor", ed.Create(c.ctx, ingress("i1", "office")), http.StatusForbidden, "ingresses/publish-public")
		want(t, "admin socket", c.admin.Create(c.ctx, ingress("i2", "office")), http.StatusForbidden, "policies can't grant privileges")
	})
	t.Run("silo grants", func(t *testing.T) {
		policy(t, "Silo", "spec.grants", `['root']`)
		want(t, "dev", dev.Create(c.ctx, silo("g1", "web3")), http.StatusForbidden, "may not use secret root-key")
		want(t, "admin socket", c.admin.Create(c.ctx, silo("g2", "web3")), http.StatusForbidden, "policies can't grant privileges")
	})
	t.Run("grant secrets", func(t *testing.T) {
		policy(t, "Grant", "spec.secrets", `[{'name': 'root-key'}]`)
		var g v1.Grant
		if err := dev.Get(c.ctx, "Grant", "web3", "none", &g); err != nil {
			t.Fatal(err)
		}
		want(t, "dev", dev.Update(c.ctx, &g), http.StatusForbidden, "may not use secret root-key")
	})
	t.Run("runtime fit", func(t *testing.T) {
		policy(t, "Silo", "spec.runtime", `'openshell'`)
		s := silo("r1", "web3")
		s.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Name: "http", Port: 8080}}}
		want(t, "a service on openshell", ed.Create(c.ctx, s), http.StatusUnprocessableEntity, "no network interface")
	})
	t.Run("vm volumes", func(t *testing.T) {
		policy(t, "Silo", "spec.volumes", `[{'name': 'root', 'mountPath': '/'}]`)
		want(t, "a volume over a VM's own disk", ed.Create(c.ctx, silo("v1", "web3")), http.StatusUnprocessableEntity, "mountPath / is the VM's own disk")
	})
	t.Run("movability", func(t *testing.T) {
		policy(t, "Silo", "spec.availability", `{'onHostLoss': 'Move'}`)
		want(t, "Move on local disks", ed.Create(c.ctx, silo("m1", "web3")), http.StatusUnprocessableEntity, "onHostLoss: Move")
	})
	t.Run("lease", func(t *testing.T) {
		policy(t, "Silo", "spec.service.lease", `{'max': '9999h'}`)
		s := silo("l1", "web3")
		s.Spec.Service = &v1.SiloService{Expose: v1.ExposeHostPort, Ports: []v1.ServicePort{{Name: "http", Port: 8080}}}
		want(t, "a lease past the cluster's limit", ada.Create(c.ctx, s), http.StatusUnprocessableEntity, "more than this cluster allows")
	})
	t.Run("kind definition", func(t *testing.T) {
		policy(t, "KindDefinition", "spec.names.shortNames", `['silo']`)
		want(t, "a defined kind shadowing a built-in", c.admin.Create(c.ctx, fromYAML(t, databasesManifest)), http.StatusUnprocessableEntity, "can't shadow a built-in")
	})
	t.Run("image versions", func(t *testing.T) {
		img := &v1.Image{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Image"}, ObjectMeta: meta.ObjectMeta{Name: "app", Namespace: "web3"},
			Spec: v1.ImageSpec{Versions: []v1.ImageVersion{{Name: "v1", Container: "docker.io/library/nginx:1.27"}}}}
		if err := ada.Create(c.ctx, img); err != nil {
			t.Fatal(err)
		}
		policy(t, "Image", "spec.versions", `[{'name': 'v1', 'container': 'docker.io/evil/nginx:1.27'}]`)
		if err := ada.Get(c.ctx, "Image", "web3", "app", img); err != nil {
			t.Fatal(err)
		}
		want(t, "a policy rewriting a version", ada.Update(c.ctx, img), http.StatusUnprocessableEntity, "can't change once added")
	})
	t.Run("secret generate", func(t *testing.T) {
		policy(t, "Secret", "spec.generate", `true`)
		if err := ada.Create(c.ctx, secretObj("fine", nil, "")); err != nil {
			t.Errorf("a policy setting another field of a secret: %v", err)
		}
	})
	t.Run("secret value in the clear", func(t *testing.T) {
		policy(t, "Secret", "spec.value", `b'aGVsbG8='`)
		want(t, "a value set by a policy", ada.Create(c.ctx, secretObj("leak", nil, "")), http.StatusUnprocessableEntity, "values are never set by policies")
	})
}
