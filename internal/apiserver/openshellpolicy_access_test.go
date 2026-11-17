package apiserver_test

import (
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// A person attaching an OpenShellPolicy that does not exist gets the same 422 as a missing grant.
// The admin socket (no person) may name one that is not there yet, and a name the silo already
// lists stays, both the same as grants. Another runtime is refused with the runtime, even when
// the policy exists.
func TestAMissingOpenShellPolicyIsRefusedLikeAGrant(t *testing.T) {
	e := setupAccess(t)
	ed := e.serviceAccount(t, "dev", "ed")
	if err := e.admin.Create(e.ctx, &v1.RoleBinding{TypeMeta: accessTM("RoleBinding"),
		ObjectMeta: meta.ObjectMeta{Name: "ed", Namespace: "dev"},
		RoleRef:    v1.RoleRef{Kind: "ClusterRole", Name: "editor"},
		Subjects:   []v1.Subject{{Kind: "ServiceAccount", Name: "ed", Namespace: "dev"}}}); err != nil {
		t.Fatal(err)
	}
	silo := func(name string, policies ...string) *v1.Silo {
		s := newSilo(name)
		s.Spec.Runtime, s.Spec.VM = "openshell", nil
		s.Spec.Container = &v1.ContainerSource{Image: "ubuntu-24.04"}
		s.Spec.OpenShellPolicies = policies
		return s
	}
	if err := ed.Create(e.ctx, silo("box", "missing")); !client.IsInvalid(err) || !strings.Contains(err.Error(), `openshell policy "missing" doesn't exist in namespace dev`) {
		t.Fatalf("a person naming a policy that doesn't exist: %v", err)
	}
	set := &v1.SiloSet{TypeMeta: accessTM("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "set", Namespace: "dev"},
		Spec: v1.SiloSetSpec{Instances: 1, Template: v1.SiloTemplate{SiloSpec: silo("set", "missing").Spec}}}
	if err := ed.Create(e.ctx, set); !client.IsInvalid(err) || !strings.Contains(err.Error(), `siloset set: openshell policy "missing" doesn't exist`) {
		t.Fatalf("a set's template naming a policy that doesn't exist: %v", err)
	}
	if err := e.admin.Create(e.ctx, silo("admin-box", "not-there")); err != nil {
		t.Fatalf("the admin socket naming a policy that doesn't exist, as it may a grant: %v", err)
	}

	pol := &v1.OpenShellPolicy{TypeMeta: accessTM("OpenShellPolicy"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.OpenShellPolicySpec{NetworkPolicies: []v1.OpenShellNetworkPolicy{{
			Name: "web", Endpoints: []v1.OpenShellEndpoint{{Host: "example.com", Port: 443, Protocol: "rest", Path: "/", Access: v1.AccessReadOnly}},
		}}}}
	if err := ed.Create(e.ctx, pol); err != nil {
		t.Fatalf("an editor creating an OpenShellPolicy: %v", err)
	}
	box := silo("box", "web")
	if err := ed.Create(e.ctx, box); err != nil {
		t.Fatalf("an openshell silo naming a policy that exists: %v", err)
	}
	box.Spec.OpenShellPolicies = []string{"web", "also-missing"}
	if err := ed.Update(e.ctx, box); !client.IsInvalid(err) || !strings.Contains(err.Error(), `openshell policy "also-missing" doesn't exist`) {
		t.Fatalf("adding a name that doesn't exist: %v", err)
	}
	if err := e.admin.Delete(e.ctx, "OpenShellPolicy", "dev", "web"); err != nil {
		t.Fatal(err)
	}
	box.Spec.OpenShellPolicies = []string{"web"}
	box.Spec.Resources.Memory = "512Mi"
	if err := ed.Update(e.ctx, box); err != nil {
		t.Fatalf("keeping a name the silo already lists, after the object is gone, as a grant does: %v", err)
	}

	other := newSilo("ct")
	other.Spec.Runtime = "docker"
	other.Spec.VM = nil
	other.Spec.Container = &v1.ContainerSource{Image: "nginx:1.27"}
	other.Spec.OpenShellPolicies = []string{"web"}
	if err := e.admin.Create(e.ctx, other); !client.IsInvalid(err) || !strings.Contains(err.Error(), "openshellPolicies is only for runtime openshell or openshell-container; docker can't use one") {
		t.Fatalf("docker naming a policy: %v", err)
	}
}
