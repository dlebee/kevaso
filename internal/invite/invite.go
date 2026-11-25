// Package invite brings a person into a cluster: a one-time code from the control plane's issuer
// (POST /admin/invites, cluster-admin only) and, if asked, a role. kvoadm users invite and kvo
// invite both use it, so an administrator who works with kvo needs no SSH for it.
//
// The role is always explicit about what it is and where it applies:
//
//	-n NS --role role/NAME          the namespaced Role NAME, in NS
//	-n NS --role clusterrole/NAME   the ClusterRole NAME, in NS only
//	--cluster-role NAME             the ClusterRole NAME, in every namespace
//
// With none, the invite carries no role: the person signs in and can do nothing until someone
// binds one.
package invite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// RoleForms names the ways to give a role, for messages.
const RoleForms = "-n NS --role role/NAME (a Role in NS), -n NS --role clusterrole/NAME (a ClusterRole, in NS only), or --cluster-role NAME (a ClusterRole, in every namespace)"

// Request is one invite: who, their groups, an optional role (Role as given to --role, with its
// role/ or clusterrole/ prefix, in Namespace; or ClusterRole for --cluster-role, cluster-wide),
// and how long the code stays valid (the server's default when empty).
type Request struct {
	User        string
	Groups      []string
	Namespace   string
	Role        string // role/NAME or clusterrole/NAME, with Namespace
	ClusterRole string // NAME, with no Namespace: every namespace
	TTL         string
}

// Binding is the role binding an invite makes (pure: what Plan decides).
type Binding struct {
	Kind      string // RoleBinding | ClusterRoleBinding
	Name      string // the binding's own name
	Namespace string // RoleBinding only
	RoleKind  string // Role | ClusterRole
	RoleName  string
}

// Describe says what the binding gives, for people.
func (b Binding) Describe() string {
	if b.Kind == "ClusterRoleBinding" {
		return "the ClusterRole " + b.RoleName + " in every namespace"
	}
	if b.RoleKind == "Role" {
		return "the Role " + b.RoleName + " in namespace " + b.Namespace
	}
	return "the ClusterRole " + b.RoleName + " in namespace " + b.Namespace
}

// Plan checks the request and says which binding it makes (nil: none). Pure.
//
// Binding names are the user and the role's kind and name, so a Role and a ClusterRole of the
// same name never share one, and inviting the same person to the same role again finds it.
func (r Request) Plan() (*Binding, error) {
	if r.User == "" {
		return nil, errors.New("invite needs NAME")
	}
	if r.Role != "" && r.ClusterRole != "" {
		return nil, errors.New("--role and --cluster-role: give one role per invite (" + RoleForms + ")")
	}
	if r.ClusterRole != "" {
		if r.Namespace != "" {
			return nil, errors.New("--cluster-role is for every namespace, so it takes no -n; for a ClusterRole in one namespace: -n " + r.Namespace + " --role clusterrole/" + r.ClusterRole)
		}
		if strings.Contains(r.ClusterRole, "/") {
			return nil, errors.New("--cluster-role takes the ClusterRole's NAME, with no prefix")
		}
		return &Binding{Kind: "ClusterRoleBinding", Name: r.User + "-clusterrole-" + r.ClusterRole, RoleKind: "ClusterRole", RoleName: r.ClusterRole}, nil
	}
	if r.Role == "" {
		return nil, nil
	}
	kind, name, ok := strings.Cut(r.Role, "/")
	switch {
	case !ok || name == "" || strings.Contains(name, "/"):
		return nil, fmt.Errorf("--role %s: say which kind of role it is: %s", r.Role, RoleForms)
	case kind != "role" && kind != "clusterrole":
		return nil, fmt.Errorf("--role %s: %s/ isn't a kind of role: %s", r.Role, kind, RoleForms)
	case r.Namespace == "":
		return nil, fmt.Errorf("--role %s needs -n NS, the namespace it applies in (for every namespace: --cluster-role NAME)", r.Role)
	}
	if kind == "role" {
		return &Binding{Kind: "RoleBinding", Name: r.User + "-role-" + name, Namespace: r.Namespace, RoleKind: "Role", RoleName: name}, nil
	}
	return &Binding{Kind: "RoleBinding", Name: r.User + "-clusterrole-" + name, Namespace: r.Namespace, RoleKind: "ClusterRole", RoleName: name}, nil
}

// Check refuses a request that can't be made (pure).
func (r Request) Check() error {
	_, err := r.Plan()
	return err
}

// Create asks first whether this caller may invite at all (the same rule the invite meets), then
// makes the role binding (so a refused role leaves no code behind), then the invite, and prints
// the two lines to send: the kvo login line for server, and the code.
func Create(ctx context.Context, c *client.Client, server string, r Request, out io.Writer) error {
	b, err := r.Plan()
	if err != nil {
		return err
	}
	var may client.CanIResponse
	if err := c.Call(ctx, http.MethodGet, "/auth/can-i?"+url.Values{"verb": {"create"}, "resource": {"invites"}}.Encode(), nil, &may); err != nil {
		return err
	}
	if !may.Allowed { // the same refusal the invite itself would get
		return &client.Error{Code: http.StatusForbidden, Reason: "Forbidden", Message: may.Reason}
	}
	if b != nil {
		if err := bind(ctx, c, r.User, *b); err != nil {
			return err
		}
	}
	var inv client.InviteResponse
	if err := c.Call(ctx, http.MethodPost, "/admin/invites", client.InviteRequest{User: r.User, Groups: r.Groups, TTL: r.TTL}, &inv); err != nil {
		return err
	}
	if b != nil {
		_, _ = fmt.Fprintf(out, "→ %s has %s\n", r.User, b.Describe())
	} else {
		_, _ = fmt.Fprintf(out, "→ %s has no role yet: they can sign in, and do nothing until one is bound (%s)\n", r.User, RoleForms)
	}
	_, _ = fmt.Fprintf(out, "→ invite for %s, valid until %s. Send them both lines:\n\n", r.User, inv.Expires.Local().Format("15:04 MST"))
	_, _ = fmt.Fprintf(out, "    kvo login %s --ca %s\n", server, inv.CAFingerprint)
	_, _ = fmt.Fprintf(out, "    invite code: %s\n\n", inv.Code)
	_, _ = fmt.Fprintln(out, "The code works once; the browser asks for it.")
	return nil
}

func bind(ctx context.Context, c *client.Client, user string, b Binding) error {
	ref := v1.RoleRef{Kind: b.RoleKind, Name: b.RoleName}
	subjects := []v1.Subject{{Kind: "User", Name: user}}
	var obj meta.Object
	switch {
	case b.Kind == "ClusterRoleBinding":
		var cr v1.ClusterRole
		if err := c.Get(ctx, "ClusterRole", "", b.RoleName, &cr); err != nil {
			return roleMissing(err, "no ClusterRole "+b.RoleName)
		}
		obj = &v1.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"},
			ObjectMeta: meta.ObjectMeta{Name: b.Name}, RoleRef: ref, Subjects: subjects}
	case b.RoleKind == "Role":
		var role v1.Role
		if err := c.Get(ctx, "Role", b.Namespace, b.RoleName, &role); err != nil {
			return roleMissing(err, "no Role "+b.RoleName+" in namespace "+b.Namespace+" (a ClusterRole by that name: --role clusterrole/"+b.RoleName+")")
		}
		obj = &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
			ObjectMeta: meta.ObjectMeta{Name: b.Name, Namespace: b.Namespace}, RoleRef: ref, Subjects: subjects}
	default:
		var cr v1.ClusterRole
		if err := c.Get(ctx, "ClusterRole", "", b.RoleName, &cr); err != nil {
			return roleMissing(err, "no ClusterRole "+b.RoleName+" (a Role in "+b.Namespace+": --role role/"+b.RoleName+")")
		}
		obj = &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
			ObjectMeta: meta.ObjectMeta{Name: b.Name, Namespace: b.Namespace}, RoleRef: ref, Subjects: subjects}
	}
	if err := c.Create(ctx, obj); err != nil && !client.IsAlreadyExists(err) {
		var ce *client.Error
		if errors.As(err, &ce) && ce.Code == http.StatusForbidden {
			return fmt.Errorf("giving %s %s was refused, nothing was invited: you can only give a role whose permissions you hold yourself (%w)", user, b.Describe(), err)
		}
		return fmt.Errorf("giving %s %s: %w", user, b.Describe(), err)
	}
	return nil
}

// roleMissing turns a NotFound into what's missing; other errors stay as they are.
func roleMissing(err error, what string) error {
	if client.IsNotFound(err) {
		return errors.New(what + ": nothing was invited")
	}
	return err
}
