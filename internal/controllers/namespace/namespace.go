// Package namespace holds the controller that deletes a namespace with what is in it (networking
// v2, "Deleting"). The API decides (internal/apiserver/nscascade.go): it judges the caller's right
// to delete everything in the namespace, then marks it with client.CascadeFinalizer. This
// controller deletes what is in it in nsdelete's order, one step at a time, each step waiting
// until what it deleted is gone, and removes the finalizer when nothing is left, which deletes the
// namespace.
//
// Where it is shows on the namespace: client.AnnotationCascadeStep. A delete the API refuses for
// good, or one refused for now (409) for longer than StuckAfter, stops it:
// client.AnnotationCascadeFailed says what is left and why, and the namespace stays Terminating
// until the delete is asked again (which clears that annotation and wakes this controller).
package namespace

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/nsdelete"
)

// Controller empties namespaces marked for the cascade, then lets them go.
type Controller struct {
	Client *client.Client
	Clock  clock.Clock
	// Wait is how long between looks while a step waits on its deletes. Default 2s.
	Wait time.Duration
	// StuckAfter is how long a step may be refused for now (409) before it stops. Default 2m.
	StuckAfter time.Duration
}

// Name implements engine.Controller.
func (c *Controller) Name() string { return "namespaces" }

// Kind implements engine.Controller.
func (c *Controller) Kind() string { return "Namespace" }

func (c *Controller) now() time.Time {
	if c.Clock == nil {
		return time.Now().UTC()
	}
	return c.Clock.Now().UTC()
}

func (c *Controller) wait() time.Duration {
	if c.Wait > 0 {
		return c.Wait
	}
	return 2 * time.Second
}

func (c *Controller) stuckAfter() time.Duration {
	if c.StuckAfter > 0 {
		return c.StuckAfter
	}
	return 2 * time.Minute
}

// Reconcile implements engine.Controller.
func (c *Controller) Reconcile(ctx context.Context, key engine.Key) (engine.Result, error) {
	var n v1.Namespace
	if err := c.Client.Get(ctx, "Namespace", "", key.Name, &n); client.IsNotFound(err) {
		return engine.Result{}, nil
	} else if err != nil {
		return engine.Result{}, err
	}
	if !slices.Contains(n.Finalizers, client.CascadeFinalizer) || n.Annotations[client.AnnotationCascadeFailed] != "" {
		return engine.Result{}, nil // not ours, or stopped until the delete is asked again
	}
	p, err := nsdelete.Step(ctx, c.Client, n.Name)
	var se *nsdelete.StepError
	if errors.As(err, &se) {
		return engine.Result{}, c.annotate(ctx, n.Name, func(a map[string]string) {
			a[client.AnnotationCascadeFailed] = se.Error() + ". Left: " + c.left(ctx, n.Name)
			delete(a, client.AnnotationCascadeSince)
		})
	}
	if err != nil {
		return engine.Result{}, err // the engine backs off and tries again
	}
	if p.Done {
		return engine.Result{}, c.release(ctx, n.Name)
	}
	step := p.String()
	since := n.Annotations[client.AnnotationCascadeSince]
	var stuck bool
	if len(p.Refused) == 0 {
		since = ""
	} else {
		at, stage := parseSince(since)
		if stage != p.Stage || at.IsZero() {
			since = strconv.Itoa(p.Stage) + " " + c.now().Format(time.RFC3339)
		} else if c.now().Sub(at) >= c.stuckAfter() {
			stuck = true
		}
	}
	err = c.annotate(ctx, n.Name, func(a map[string]string) {
		a[client.AnnotationCascadeStep] = step
		if since == "" {
			delete(a, client.AnnotationCascadeSince)
		} else {
			a[client.AnnotationCascadeSince] = since
		}
		if stuck {
			a[client.AnnotationCascadeFailed] = "step " + strconv.Itoa(p.Stage+1) + "/" + strconv.Itoa(len(nsdelete.Stages)) + ", " +
				nsdelete.Stages[p.Stage].Name + ": refused for " + c.stuckAfter().String() + ": " + strings.Join(p.Refused, "; ") +
				". Left: " + c.left(ctx, n.Name)
			delete(a, client.AnnotationCascadeSince)
		}
	})
	if err != nil || stuck {
		return engine.Result{}, err
	}
	return engine.Result{RequeueAfter: c.wait()}, nil
}

// left describes everything the namespace still holds, for a failure.
func (c *Controller) left(ctx context.Context, ns string) string {
	items, err := nsdelete.Contents(ctx, c.Client, ns)
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	if len(items) == 0 {
		return "nothing"
	}
	return nsdelete.Describe(items)
}

// parseSince reads AnnotationCascadeSince: "STAGE TIME".
func parseSince(v string) (time.Time, int) {
	st, at, ok := strings.Cut(v, " ")
	if !ok {
		return time.Time{}, -1
	}
	stage, err := strconv.Atoi(st)
	if err != nil {
		return time.Time{}, -1
	}
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return time.Time{}, -1
	}
	return t, stage
}

// annotate changes the namespace's annotations, writing only when they change (each write wakes
// this controller again).
func (c *Controller) annotate(ctx context.Context, name string, change func(map[string]string)) error {
	var n v1.Namespace
	if err := c.Client.Get(ctx, "Namespace", "", name, &n); err != nil {
		return err
	}
	next := maps.Clone(n.Annotations)
	if next == nil {
		next = map[string]string{}
	}
	change(next)
	if maps.Equal(n.Annotations, next) {
		return nil
	}
	n.Annotations = next
	return c.Client.Update(ctx, &n)
}

// release removes the finalizer and the cascade's annotations: the namespace, empty and marked
// for deletion, goes with the write.
func (c *Controller) release(ctx context.Context, name string) error {
	var n v1.Namespace
	if err := c.Client.Get(ctx, "Namespace", "", name, &n); client.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}
	n.Finalizers = slices.DeleteFunc(slices.Clone(n.Finalizers), func(f string) bool { return f == client.CascadeFinalizer })
	delete(n.Annotations, client.AnnotationCascadeStep)
	delete(n.Annotations, client.AnnotationCascadeSince)
	err := c.Client.Update(ctx, &n)
	if client.IsNotFound(err) {
		return nil
	}
	return err
}
