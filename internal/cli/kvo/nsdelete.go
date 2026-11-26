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
	"kevaso.com/core/internal/nsdelete"
)

// Deleting a namespace with what is in it, and deleting everything in one (networking v2,
// "Deleting"). Both list what is there and ask once; --yes is that yes. With no terminal to ask
// on and no --yes, they refuse and name the flag.
//
//	kvo delete namespace X     the API deletes what is in it in order, then the namespace; kvo
//	                           follows until it is gone or a step stops (run it again to resume)
//	kvo delete all -n X        kvo deletes everything in X in the same order; X stays

// askTerminal reports whether there is a person at stdin to ask. A variable for tests.
var askTerminal = func(stdin io.Reader) bool {
	f, ok := stdin.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// followEvery is how often kvo looks while a namespace empties; stuckAfter is how long kvo
// delete all waits out a step refused for now (409) before it stops. Variables for tests.
var (
	followEvery = time.Second
	stuckAfter  = 2 * time.Minute
)

// confirm asks question on stdout and reads a yes from stdin.
func confirm(stdin io.Reader, stdout io.Writer, question string) bool {
	_, _ = fmt.Fprint(stdout, question+" Are you sure? [y/N] ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	a := strings.TrimSpace(strings.ToLower(line))
	return a == "y" || a == "yes"
}

// deleteNamespace is kvo delete namespace NAME.
func deleteNamespace(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout io.Writer) error {
	name := o.args[1]
	plan, err := c.PlanNamespaceDelete(ctx, name)
	if err != nil {
		return err
	}
	if len(plan.Items) > 0 && !o.sets.yes {
		held := fmt.Sprintf("namespace %s still holds resources: %s.", name, plan.Summary)
		if !askTerminal(stdin) {
			return fmt.Errorf("%s Deleting the namespace deletes all of them: run again with --yes to go ahead (there is no terminal here to ask on)", held)
		}
		if !confirm(stdin, stdout, held+"\nDeleting the namespace deletes all of them first ("+strings.Join(plan.Stages, ", ")+").") {
			return errors.New("not deleted")
		}
	}
	opts := client.DeleteOptions{Cascade: true}
	if !o.sets.yes {
		opts.Plan = plan.ID // the yes is for what was shown
	}
	if err := c.DeleteNamespace(ctx, name, opts); err != nil {
		return err
	}
	return followNamespace(ctx, c, name, stdout) // empty: already gone; or resumed with nothing left but the release
}

// followNamespace prints each step of namespace name's cascade until it is gone, or the step that
// stopped and why.
func followNamespace(ctx context.Context, c *client.Client, name string, stdout io.Writer) error {
	last := ""
	for {
		var n v1.Namespace
		err := c.Get(ctx, "Namespace", "", name, &n)
		if client.IsNotFound(err) {
			_, _ = fmt.Fprintf(stdout, "namespace/%s deleted\n", name)
			return nil
		}
		if err != nil {
			return err
		}
		if f := n.Annotations[client.AnnotationCascadeFailed]; f != "" {
			return fmt.Errorf("namespace %s: deleting what is in it stopped at %s. It stays Terminating; kvo delete namespace %s runs it again from there", name, f, name)
		}
		if st := n.Annotations[client.AnnotationCascadeStep]; st != "" && st != last && st != "starting" {
			_, _ = fmt.Fprintln(stdout, st)
			last = st
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped following; namespace %s is still being deleted (kvo describe namespace %s shows where it is)", name, name)
		case <-time.After(followEvery):
		}
	}
}

// deleteAll is kvo delete all -n NS: everything in NS, secrets included, in nsdelete's order; NS
// stays. What the caller may not delete is named first, and then nothing is deleted.
func deleteAll(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout io.Writer) error {
	if len(o.args) != 1 {
		return errors.New("delete all takes no name: kvo delete all -n NAMESPACE")
	}
	ns := defaultNS(o)
	var n v1.Namespace
	if err := c.Get(ctx, "Namespace", "", ns, &n); err != nil {
		return err
	}
	items, err := nsdelete.Contents(ctx, c, ns)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		_, _ = fmt.Fprintf(stdout, "namespace %s holds nothing\n", ns)
		return nil
	}
	refused, why, err := mayNotDelete(ctx, c, ns, items)
	if err != nil {
		return err
	}
	if len(refused) > 0 {
		return fmt.Errorf("you may not delete %s in namespace %s (%s): nothing was deleted", nsdelete.Describe(refused), ns, strings.Join(why, "; "))
	}
	if !o.sets.yes {
		held := fmt.Sprintf("namespace %s holds resources: %s.", ns, nsdelete.Summary(items))
		if !askTerminal(stdin) {
			return fmt.Errorf("%s kvo delete all deletes all of them: run again with --yes to go ahead (there is no terminal here to ask on)", held)
		}
		if !confirm(stdin, stdout, held+"\nThis deletes all of them ("+strings.Join(nsdelete.StageNames(), ", ")+"); the namespace stays.") {
			return errors.New("nothing deleted")
		}
	}
	last, refusedSince := "", time.Time{}
	for {
		p, err := nsdelete.Step(ctx, c, ns)
		var se *nsdelete.StepError
		if errors.As(err, &se) {
			return fmt.Errorf("%v. Nothing of a later step was deleted; kvo delete all -n %s runs it again from there", se, ns)
		}
		if err != nil {
			return err
		}
		if p.Done {
			_, _ = fmt.Fprintf(stdout, "deleted everything in namespace %s\n", ns)
			return nil
		}
		if s := p.String(); s != last {
			_, _ = fmt.Fprintln(stdout, s)
			last = s
		}
		switch {
		case len(p.Refused) == 0:
			refusedSince = time.Time{}
		case refusedSince.IsZero():
			refusedSince = time.Now()
		case time.Since(refusedSince) >= stuckAfter:
			return fmt.Errorf("step %d/%d, %s: refused for %s: %s. Nothing of a later step was deleted; kvo delete all -n %s runs it again from there",
				p.Stage+1, len(nsdelete.Stages), nsdelete.Stages[p.Stage].Name, stuckAfter, strings.Join(p.Refused, "; "), ns)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped at %s; kvo delete all -n %s runs it again from there", last, ns)
		case <-time.After(followEvery):
		}
	}
}

// mayNotDelete asks the server, per object, whether the caller may delete it. A server without
// sign-in (no /auth/can-i) lets anyone do anything.
func mayNotDelete(ctx context.Context, c *client.Client, ns string, items []client.CascadeItem) ([]client.CascadeItem, []string, error) {
	var refused []client.CascadeItem
	var why []string
	seen := map[string]bool{}
	for _, it := range items {
		resource := it.Kind // a defined kind's is PLURAL.GROUP
		if k, ok := v1.Lookup(it.Kind); ok && !strings.Contains(it.Kind, ".") {
			resource = k.Plural
		}
		q := url.Values{"verb": {"delete"}, "resource": {resource}, "namespace": {ns}, "name": {it.Name}}
		var ans client.CanIResponse
		err := c.Call(ctx, http.MethodGet, "/auth/can-i?"+q.Encode(), nil, &ans)
		var ce *client.Error
		if errors.As(err, &ce) && ce.Code == http.StatusNotFound {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		if !ans.Allowed {
			refused = append(refused, it)
			if !seen[ans.Reason] {
				seen[ans.Reason] = true
				why = append(why, ans.Reason)
			}
		}
	}
	return refused, why, nil
}
