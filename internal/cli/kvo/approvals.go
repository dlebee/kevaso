package kvo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

// approve answers a pending approval (design §8.7): kvo approve NAME | kvo deny NAME [--reason R].
// It needs the verb approve on the secret the approval asks for; a service account's token never
// can, whatever its roles.
func approve(ctx context.Context, c *client.Client, o opts, verb string, stdout io.Writer) error {
	if len(o.args) != 1 {
		return fmt.Errorf("%s needs the approval's NAME (kvo get approvals)", verb)
	}
	ns := defaultNS(o)
	path := "/apis/kevaso/v1/namespaces/" + url.PathEscape(ns) + "/approvals/" + url.PathEscape(o.args[0]) + "/" + verb
	var a v1.Approval
	if err := c.Call(ctx, http.MethodPost, path, client.ApprovalAnswer{Reason: o.reason}, &a); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, approvalLine(&a))
	return err
}

// approvalLine says what was answered, for people.
func approvalLine(a *v1.Approval) string {
	what := fmt.Sprintf("approval/%s: silo %s, %s", a.Name, a.Spec.Silo, a.Spec.Summary)
	switch a.Status.Phase {
	case v1.ApprovalApproved:
		return fmt.Sprintf("%s: approved until %s", what, a.Status.AccessUntil.Local().Format(time.Kitchen))
	case v1.ApprovalDenied:
		return what + ": denied"
	}
	return what + ": " + a.Status.Phase
}

// approvalColumns are kvo get approvals' columns.
func approvalColumns(a *v1.Approval, now time.Time) []string {
	phase := a.Status.Phase
	when := "-"
	switch {
	case phase == v1.ApprovalPending && !now.Before(a.Spec.ExpiresAt):
		phase = v1.ApprovalExpired
	case phase == v1.ApprovalPending:
		when = "expires in " + a.Spec.ExpiresAt.Sub(now).Round(time.Second).String()
	case phase == v1.ApprovalApproved && a.Status.AccessUntil != nil && now.Before(*a.Status.AccessUntil):
		when = "until " + a.Status.AccessUntil.Local().Format(time.Kitchen)
	case phase == v1.ApprovalApproved:
		phase, when = "Used", "access ended"
	}
	return []string{a.Spec.Silo, a.Spec.Secret, a.Spec.Use, a.Spec.For, phase, when, dash(a.Status.AnsweredBy)}
}
