package kvo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/approvals"
)

// approve answers a pending approval (design §8.7): kvo approve NAME [--request ID] | kvo deny
// NAME [--reason R]. It needs the verb approve on the secret the approval asks for; a service
// account's token never can, whatever its roles.
//
// A yes is for the request the person read (K-017): --request is its ID from kvo get approvals.
// Without it, on a terminal, the request is shown and the yes is for what was shown; elsewhere
// it is refused. Either way, a request asked again with anything else since is not approved.
func approve(ctx context.Context, c *client.Client, o opts, verb string, stdin io.Reader, stdout io.Writer) error {
	if len(o.args) != 1 {
		return fmt.Errorf("%s needs the approval's NAME (kvo get approvals)", verb)
	}
	ns := defaultNS(o)
	request := o.request
	if verb == "approve" && request == "" {
		f, ok := stdin.(*os.File)
		if !ok || !term.IsTerminal(int(f.Fd())) {
			return fmt.Errorf("approve %s: say which request with --request ID (the REQUEST column of kvo get approvals)", o.args[0])
		}
		var cur v1.Approval
		if err := c.Get(ctx, "Approval", ns, o.args[0], &cur); err != nil {
			return err
		}
		cols := approvalColumns(&cur, time.Now())
		_, _ = fmt.Fprintf(stdout, "approval/%s: silo %s asks to %s %s for %s: %s\napprove this request (%s)? [y/N] ",
			cur.Name, cur.Spec.Silo, cur.Spec.Use, plain(cols[1], 80), cur.Spec.For, plain(cur.Spec.Summary, 200), approvals.RequestID(&cur))
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if a := strings.TrimSpace(strings.ToLower(line)); a != "y" && a != "yes" {
			return errors.New("not approved")
		}
		request = approvals.RequestID(&cur)
	}
	path := "/apis/kevaso/v1/namespaces/" + url.PathEscape(ns) + "/approvals/" + url.PathEscape(o.args[0]) + "/" + verb
	var a v1.Approval
	if err := c.Call(ctx, http.MethodPost, path, client.ApprovalAnswer{Reason: o.reason, Request: request}, &a); err != nil {
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
	what := a.Spec.Secret
	if a.Spec.Use == v1.ApprovalForExpose {
		what = "port " + a.Spec.Port
	}
	return []string{a.Spec.Silo, what, a.Spec.Use, a.Spec.For, phase, when, dash(a.Status.AnsweredBy), approvals.RequestID(a)}
}
