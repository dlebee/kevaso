package apiserver_test

import (
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/rbac"
)

// K-016 (design §0.8): a role or binding can't grant more than its author holds. The matrix:
// authors (namespace admin, a narrow author who can write roles, a cluster admin, a plugin's
// service account, the admin socket) against grants (a Role, a ClusterRole, a binding of an
// existing role, a binding of a missing role, a defined kind's resource), each with what the
// author holds and what is beyond it.

func rule(res string, verbs ...string) v1.PolicyRule {
	return v1.PolicyRule{Verbs: verbs, Resources: []string{res}}
}

func roleOf(ns, name string, rules ...v1.PolicyRule) *v1.Role {
	return &v1.Role{TypeMeta: accessTM("Role"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns}, Rules: rules}
}

func cRoleOf(name string, rules ...v1.PolicyRule) *v1.ClusterRole {
	return &v1.ClusterRole{TypeMeta: accessTM("ClusterRole"), ObjectMeta: meta.ObjectMeta{Name: name}, Rules: rules}
}

func rbOf(ns, name, kind, role string) *v1.RoleBinding {
	return &v1.RoleBinding{TypeMeta: accessTM("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns},
		RoleRef: v1.RoleRef{Kind: kind, Name: role}, Subjects: []v1.Subject{{Kind: "User", Name: "victim"}}}
}

func crbOf(name, role string) *v1.ClusterRoleBinding {
	return &v1.ClusterRoleBinding{TypeMeta: accessTM("ClusterRoleBinding"), ObjectMeta: meta.ObjectMeta{Name: name},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: role}, Subjects: []v1.Subject{{Kind: "User", Name: "victim"}}}
}

// bindIn binds the built-in or custom ClusterRole to the service account in the namespace.
func (e *accessEnv) bindIn(t *testing.T, ns, name, clusterRole, saNS, sa string) {
	t.Helper()
	if err := e.admin.Create(e.ctx, &v1.RoleBinding{TypeMeta: accessTM("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns},
		RoleRef:  v1.RoleRef{Kind: "ClusterRole", Name: clusterRole},
		Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: sa, Namespace: saNS}}}); err != nil {
		t.Fatal(err)
	}
}

func (e *accessEnv) clusterBind(t *testing.T, name, clusterRole, saNS, sa string) {
	t.Helper()
	if err := e.admin.Create(e.ctx, &v1.ClusterRoleBinding{TypeMeta: accessTM("ClusterRoleBinding"), ObjectMeta: meta.ObjectMeta{Name: name},
		RoleRef:  v1.RoleRef{Kind: "ClusterRole", Name: clusterRole},
		Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: sa, Namespace: saNS}}}); err != nil {
		t.Fatal(err)
	}
}

func TestRolesCannotGrantMoreThanTheirAuthorHolds(t *testing.T) {
	e := setupAccess(t)
	for _, n := range []string{"team", "other"} {
		if err := e.admin.Create(e.ctx, ns(n)); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range rbac.BuiltinRoles() {
		if err := e.admin.Create(e.ctx, r); err != nil && !client.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	// A role the narrow author doesn't hold, made by the admin socket; and a defined kind.
	if err := e.admin.Create(e.ctx, cRoleOf("wide", rule("silos", "get", "list", "create", "update", "delete"))); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Create(e.ctx, cRoleOf("small", rule("silos", "get"))); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Create(e.ctx, dbDefinition(t, `{"type":"object","properties":{"spec":{"type":"object"}}}`)); err != nil {
		t.Fatal(err)
	}

	nsAdmin := e.serviceAccount(t, "team", "admin-sa")
	e.bindIn(t, "team", "admin-sa", "admin", "team", "admin-sa")

	// The narrow author writes roles and bindings in team, and holds: get silos, get and list
	// services (two rules), list+use+write secrets, get databases (a defined kind), update grants
	// named a.
	narrow := e.serviceAccount(t, "team", "narrow")
	if err := e.admin.Create(e.ctx, cRoleOf("narrow-powers",
		rule("roles", "get", "create", "update", "delete"), rule("rolebindings", "get", "create", "update", "delete"),
		rule("silos", "get"), rule("services", "get"), rule("services", "list"),
		rule("secrets", "list", v1.VerbUse), rule("secrets", v1.VerbWrite),
		rule("databases", "get"),
		v1.PolicyRule{Verbs: []string{"update"}, Resources: []string{"grants"}, ResourceNames: []string{"a"}},
	)); err != nil {
		t.Fatal(err)
	}
	e.bindIn(t, "team", "narrow", "narrow-powers", "team", "narrow")

	root := e.serviceAccount(t, "team", "root-sa")
	e.clusterBind(t, "root-sa", "cluster-admin", "team", "root-sa")

	// A plugin's service account (kevaso-plugins) that may write roles cluster-wide, and holds
	// get hosts and get leases.
	plugin := e.serviceAccount(t, "kevaso-plugins", "plugin-x")
	e.grant(t, "x-ops", "kevaso-plugins", "plugin-x",
		rule("clusterroles", "get", "create", "update"), rule("clusterrolebindings", "get", "create"),
		rule("roles", "create"), rule("rolebindings", "create"), rule("hosts", "get"), rule("leases", "get"))

	ok, no := http.StatusCreated, http.StatusForbidden
	type step struct {
		who  string
		c    *client.Client
		obj  meta.Object
		want int
	}
	admin := e.admin
	steps := []step{
		// A namespace admin: everything the built-in admin role holds, nothing beyond.
		{"nsadmin: role with its own powers", nsAdmin, roleOf("team", "r-ok", rule("silos", "get", "create"), rule("secrets", "list", v1.VerbUse)), ok},
		{"nsadmin: role with a subresource it holds", nsAdmin, roleOf("team", "r-exec", rule("silos/exec", "create")), ok},
		{"nsadmin: role with * on *", nsAdmin, roleOf("team", "r-star", rule("*", "*")), no},
		{"nsadmin: role with get on hosts", nsAdmin, roleOf("team", "r-hosts", rule("hosts", "get")), no},
		{"nsadmin: role with * verbs on silos", nsAdmin, roleOf("team", "r-sverb", rule("silos", "*")), no},
		{"nsadmin: role with */status", nsAdmin, roleOf("team", "r-status", rule("*/status", "update")), no},
		{"nsadmin: role with silos/status", nsAdmin, roleOf("team", "r-sstatus", rule("silos/status", "update")), no},
		{"nsadmin: role naming secrets read-value is held", nsAdmin, roleOf("team", "r-rv", rule("secrets", v1.VerbReadValue)), ok},
		{"nsadmin: role in another namespace", nsAdmin, roleOf("other", "r-other", rule("silos", "get")), no},
		{"nsadmin: clusterrole", nsAdmin, cRoleOf("c-small", rule("silos", "get")), no},
		{"nsadmin: bind built-in admin", nsAdmin, rbOf("team", "b-admin", "ClusterRole", "admin"), ok},
		{"nsadmin: bind built-in viewer", nsAdmin, rbOf("team", "b-viewer", "ClusterRole", "viewer"), ok},
		{"nsadmin: bind cluster-admin", nsAdmin, rbOf("team", "b-ca", "ClusterRole", "cluster-admin"), no},
		{"nsadmin: bind a role that doesn't exist yet", nsAdmin, rbOf("team", "b-missing", "Role", "later"), no},
		{"nsadmin: bind a clusterrole that doesn't exist yet", nsAdmin, rbOf("team", "b-cmissing", "ClusterRole", "later"), no},
		{"nsadmin: bind the role it just made", nsAdmin, rbOf("team", "b-r-ok", "Role", "r-ok"), ok},
		{"nsadmin: clusterrolebinding", nsAdmin, crbOf("cb-viewer", "viewer"), no},

		// A narrow author: only what it holds, rule by rule and verb by verb.
		{"narrow: get silos", narrow, roleOf("team", "n-get", rule("silos", "get")), ok},
		{"narrow: get+list services across two held rules", narrow, roleOf("team", "n-svc", rule("services", "get", "list")), ok},
		{"narrow: create silos", narrow, roleOf("team", "n-create", rule("silos", "create")), no},
		{"narrow: one rule, one held and one not", narrow, roleOf("team", "n-mixed", rule("silos", "get", "list")), no},
		{"narrow: a second rule beyond", narrow, roleOf("team", "n-two", rule("silos", "get"), rule("ips", "get")), no},
		{"narrow: any resource", narrow, roleOf("team", "n-any", rule("*", "get")), no},
		{"narrow: secrets use and list held", narrow, roleOf("team", "n-sec", rule("secrets", "get", "list", v1.VerbUse)), ok},
		{"narrow: secrets write held covers create", narrow, roleOf("team", "n-secw", rule("secrets", "create", "delete")), ok},
		{"narrow: secrets approve not held", narrow, roleOf("team", "n-seca", rule("secrets", v1.VerbApprove)), no},
		{"narrow: secrets read-value not held", narrow, roleOf("team", "n-secr", rule("secrets", v1.VerbReadValue)), no},
		{"narrow: defined kind held", narrow, roleOf("team", "n-db", rule("databases", "get")), ok},
		{"narrow: defined kind write", narrow, roleOf("team", "n-dbw", rule("databases", "create", "update")), no},
		{"narrow: defined kind status", narrow, roleOf("team", "n-dbs", rule("databases/status", "get")), no},
		{"narrow: every resource of a defined kind's group", narrow, roleOf("team", "n-dbstar", rule("*", "get")), no},
		{"narrow: grants named a is held", narrow, roleOf("team", "n-ga", v1.PolicyRule{Verbs: []string{"update"}, Resources: []string{"grants"}, ResourceNames: []string{"a"}}), ok},
		{"narrow: grants named b", narrow, roleOf("team", "n-gb", v1.PolicyRule{Verbs: []string{"update"}, Resources: []string{"grants"}, ResourceNames: []string{"b"}}), no},
		{"narrow: grants named a and b", narrow, roleOf("team", "n-gab", v1.PolicyRule{Verbs: []string{"update"}, Resources: []string{"grants"}, ResourceNames: []string{"a", "b"}}), no},
		{"narrow: every grant", narrow, roleOf("team", "n-gall", rule("grants", "update")), no},
		{"narrow: bind small (get silos)", narrow, rbOf("team", "nb-small", "ClusterRole", "small"), ok},
		{"narrow: bind wide, which the admin wrote", narrow, rbOf("team", "nb-wide", "ClusterRole", "wide"), no},
		{"narrow: bind cluster-admin", narrow, rbOf("team", "nb-ca", "ClusterRole", "cluster-admin"), no},
		{"narrow: bind a Role it couldn't have written", narrow, rbOf("team", "nb-admin-made", "Role", "r-ok"), no},
		{"narrow: bind a missing role", narrow, rbOf("team", "nb-missing", "ClusterRole", "nonesuch"), no},

		// A cluster admin: holds everything, so everything passes, a missing role included.
		{"root: role with * on *", root, roleOf("team", "root-star", rule("*", "*")), ok},
		{"root: clusterrole with *", root, cRoleOf("root-c", rule("*", "*")), ok},
		{"root: bind cluster-admin", root, crbOf("root-cb", "cluster-admin"), ok},
		{"root: bind a missing role", root, rbOf("team", "root-missing", "ClusterRole", "later"), ok},

		// A plugin's service account: cluster-wide powers of its own only.
		{"plugin: clusterrole with get hosts", plugin, cRoleOf("p-hosts", rule("hosts", "get")), ok},
		{"plugin: clusterrole with write on hosts", plugin, cRoleOf("p-hostsw", rule("hosts", "update")), no},
		{"plugin: clusterrole with * ", plugin, cRoleOf("p-star", rule("*", "*")), no},
		{"plugin: role in a namespace with get leases", plugin, roleOf("team", "p-leases", rule("leases", "get")), ok},
		{"plugin: clusterrolebinding to cluster-admin", plugin, crbOf("p-cb", "cluster-admin"), no},
		{"plugin: clusterrolebinding to its own kind of role", plugin, crbOf("p-cb2", "p-hosts"), ok},
		{"plugin: rolebinding to cluster-admin in a namespace", plugin, rbOf("team", "p-rb", "ClusterRole", "cluster-admin"), no},

		// The admin socket has no roles and is never asked.
		{"socket: role with * on *", admin, roleOf("team", "s-star", rule("*", "*")), ok},
		{"socket: bind a missing role", admin, rbOf("team", "s-missing", "ClusterRole", "later"), ok},
	}
	for _, s := range steps {
		err := s.c.Create(e.ctx, s.obj)
		got := http.StatusCreated
		if err != nil {
			got = code(err)
		}
		if got != s.want {
			t.Errorf("%s: %d (%v), want %d", s.who, got, err, s.want)
		}
	}

	// A refusal says what is missing.
	err := nsAdmin.Create(e.ctx, roleOf("team", "says-what", rule("hosts", "get")))
	if err == nil || !contains(err.Error(), "would grant permissions you don't hold in namespace team") || !contains(err.Error(), "get hosts") {
		t.Errorf("refusal text: %v", err)
	}

	// Updates: the narrow author can't widen a role it wrote, can still change its labels, and
	// can't widen a binding's role to one it doesn't hold.
	var r v1.Role
	if err := narrow.Get(e.ctx, "Role", "team", "n-get", &r); err != nil {
		t.Fatal(err)
	}
	r.Rules = []v1.PolicyRule{rule("silos", "get", "delete")}
	if err := narrow.Update(e.ctx, &r); code(err) != no {
		t.Errorf("widening an own role: %v, want 403", err)
	}
	r.Rules = []v1.PolicyRule{rule("silos", "get")}
	r.Labels = map[string]string{"x": "y"}
	if err := narrow.Update(e.ctx, &r); err != nil {
		t.Errorf("a label on a role with the same rules: %v", err)
	}
	// A role the admin socket wrote with more than the narrow author holds: its labels can change,
	// its rules can't (a person can't reuse what they couldn't have written).
	var wideRole v1.Role
	if err := e.admin.Create(e.ctx, roleOf("team", "admin-made", rule("silos", "get", "delete"))); err != nil {
		t.Fatal(err)
	}
	if err := narrow.Get(e.ctx, "Role", "team", "admin-made", &wideRole); err != nil {
		t.Fatal(err)
	}
	wideRole.Labels = map[string]string{"x": "y"}
	if err := narrow.Update(e.ctx, &wideRole); err != nil {
		t.Errorf("a label on a role it couldn't have written: %v", err)
	}
	wideRole.Rules = append(wideRole.Rules, rule("silos", "list"))
	if err := narrow.Update(e.ctx, &wideRole); code(err) != no {
		t.Errorf("editing the rules of a role it doesn't hold: %v, want 403", err)
	}
	var b v1.RoleBinding
	if err := narrow.Get(e.ctx, "RoleBinding", "team", "nb-small", &b); err != nil {
		t.Fatal(err)
	}
	b.RoleRef = v1.RoleRef{Kind: "ClusterRole", Name: "wide"}
	if err := narrow.Update(e.ctx, &b); code(err) != no {
		t.Errorf("repointing a binding at a wide role: %v, want 403", err)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
