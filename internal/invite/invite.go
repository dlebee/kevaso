// Package invite brings a person into a cluster: a one-time code from the control plane's issuer
// (POST /admin/invites, cluster-admin only) and, if asked, a role in a namespace. kvoadm users
// invite and kvo invite both use it, so an administrator who works with kvo needs no SSH for it.
package invite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Request is one invite: who, their groups, a role in a namespace (editor by default when a
// namespace is named), and how long the code stays valid (the server's default when empty).
type Request struct {
	User      string
	Groups    []string
	Namespace string
	Role      string
	TTL       string
}

// Check refuses a request that can't be made (pure).
func (r Request) Check() error {
	if r.User == "" {
		return errors.New("invite needs NAME")
	}
	if r.Role != "" && r.Namespace == "" {
		return errors.New("--role needs --namespace")
	}
	return nil
}

// Create makes the invite (and the role binding) and prints the two lines to send: the kvo login
// line for server, and the code.
func Create(ctx context.Context, c *client.Client, server string, r Request, out io.Writer) error {
	if err := r.Check(); err != nil {
		return err
	}
	var inv client.InviteResponse
	if err := c.Call(ctx, http.MethodPost, "/admin/invites", client.InviteRequest{User: r.User, Groups: r.Groups, TTL: r.TTL}, &inv); err != nil {
		return err
	}
	if r.Namespace != "" {
		role := r.Role
		if role == "" {
			role = "editor"
		}
		rb := &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
			ObjectMeta: meta.ObjectMeta{Name: r.User + "-" + role, Namespace: r.Namespace},
			RoleRef:    v1.RoleRef{Kind: "ClusterRole", Name: role}, Subjects: []v1.Subject{{Kind: "User", Name: r.User}}}
		if err := c.Create(ctx, rb); err != nil && !client.IsAlreadyExists(err) {
			return fmt.Errorf("binding %s as %s in %s: %w", r.User, role, r.Namespace, err)
		}
		_, _ = fmt.Fprintf(out, "→ %s is %s in namespace %s\n", r.User, role, r.Namespace)
	}
	_, _ = fmt.Fprintf(out, "→ invite for %s, valid until %s. Send them both lines:\n\n", r.User, inv.Expires.Local().Format("15:04 MST"))
	_, _ = fmt.Fprintf(out, "    kvo login %s --ca %s\n", server, inv.CAFingerprint)
	_, _ = fmt.Fprintf(out, "    invite code: %s\n\n", inv.Code)
	_, _ = fmt.Fprintln(out, "The code works once; the browser asks for it.")
	return nil
}
