package apiserver

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/nsdelete"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

// Deleting a namespace with what is in it (networking v2, "Deleting"; api/client/cascade.go).
//
// The API decides, the controller deletes. A cascade delete is judged here once, whole: what
// outside names the namespace refuses it (409), and so does anything in it the caller may not
// delete (403, each named). Nothing is deleted then, and the namespace is Active again. Otherwise
// the namespace is marked: Terminating (nothing new can be made in it), the cascade finalizer, and
// who asked. kevasod's namespace controller (internal/controllers/namespace) deletes what is in it
// in nsdelete's order and removes the finalizer when it is empty, which deletes the namespace.
//
// The set it deletes is closed once marked: a create in a Terminating namespace is refused, a
// controller's too. So the RBAC judged here covers everything the controller will delete.
//
// A step that fails stops the controller (AnnotationCascadeFailed says what is left and why) and
// the namespace stays Terminating. The same delete again resumes it: what is left is judged again
// for this caller, the failure is cleared, and the controller wakes.

// checkCascade judges a cascade of items (what namespace ns holds) for the caller: the 403 naming
// what they may not delete, the 409 when a plan was passed and the namespace holds anything else
// now, or the plan.
func (s *Server) checkCascade(ctx context.Context, ns string, items []client.CascadeItem, wantPlan string) (*client.NamespacePlan, error) {
	refused, reasons, err := s.notDeletable(ctx, ns, items)
	if err != nil {
		return nil, err
	}
	if len(refused) > 0 {
		who := "you"
		if id, ok := IdentityFrom(ctx); ok {
			who = id.String()
		}
		return nil, errf(http.StatusForbidden, "Forbidden", "%s may not delete %s in namespace %s (%s): nothing was deleted. "+
			"Deleting a namespace with what is in it takes the right to delete each thing in it: ask an admin of %s, or delete the rest yourself",
			who, nsdelete.Describe(refused), ns, strings.Join(reasons, "; "), ns)
	}
	plan := nsdelete.Plan(ns, items)
	if wantPlan != "" && wantPlan != plan.ID {
		return nil, errf(http.StatusConflict, "Conflict", "namespace %s holds something else now (%s): nothing was deleted; look again (kvo delete namespace %s asks with what is there now)",
			ns, plan.Summary, ns)
	}
	return plan, nil
}

// notDeletable are the items the caller may not delete, by the same rules a DELETE of each would
// meet, and why (one reason each, deduplicated). An unauthenticated server, the admin socket and
// kevasod itself may delete anything.
func (s *Server) notDeletable(ctx context.Context, ns string, items []client.CascadeItem) ([]client.CascadeItem, []string, error) {
	id, ok := IdentityFrom(ctx)
	if !ok || id == LocalAdmin || id == Component {
		return nil, nil, nil
	}
	groups, _ := ctx.Value(groupsKey).([]string)
	set, err := s.definedKinds(ctx)
	if err != nil {
		return nil, nil, err
	}
	var refused []client.CascadeItem
	reasons := map[string]bool{}
	for _, it := range items {
		t := target{namespace: ns, name: it.Name}
		if k, ok := v1.Lookup(it.Kind); ok && !strings.Contains(it.Kind, ".") {
			t.kind = k
		} else {
			var dk *definedKind
			for _, d := range set.list {
				if d.res.Resource == it.Kind {
					dk = d
				}
			}
			if dk == nil { // its definition went since the look: refuse, rather than judge it as nothing
				refused = append(refused, it)
				reasons["kind "+it.Kind+" is no longer defined"] = true
				continue
			}
			t.kind, t.def = dk.info(), dk
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodDelete, "/", nil)
		if err != nil {
			return nil, nil, err
		}
		allowed, _, reason, err := s.authorizeRequest(ctx, id, groups, r, t)
		if err != nil {
			return nil, nil, err
		}
		if !allowed {
			refused = append(refused, it)
			reasons[reason] = true
		}
	}
	return refused, slices.Sorted(maps.Keys(reasons)), nil
}

// startCascade marks namespace name, as checkDeleteNamespace marked it (revision rev), for the
// cascade: the finalizer, the deletion time and who asked. It returns the revision written; the
// delete then answers 202, and the finalizer holds the namespace until the controller is done.
func (s *Server) startCascade(ctx context.Context, name string, rev int64) (int64, error) {
	return s.writeNamespace(ctx, name, rev, func(n *v1.Namespace) {
		if n.Annotations == nil {
			n.Annotations = map[string]string{}
		}
		n.Finalizers = append(n.Finalizers, client.CascadeFinalizer)
		if n.DeletionTimestamp == nil { // with the finalizer, in one write: the controller never sees one without the other
			now := s.clock.Now().UTC().Truncate(time.Second)
			n.DeletionTimestamp = &now
		}
		n.Annotations[client.AnnotationCascadeBy] = cascadeCaller(ctx) + " at " + s.clock.Now().UTC().Format(time.RFC3339)
		n.Annotations[client.AnnotationCascadeStep] = "starting"
		delete(n.Annotations, client.AnnotationCascadeFailed)
		delete(n.Annotations, client.AnnotationCascadeSince)
	})
}

// resumeCascade is a cascade delete of a namespace already being deleted with what is in it: what
// is left is judged again for this caller, then the failure (if any) is cleared and the controller
// woken. Its plan, on a dry run.
func (s *Server) resumeCascade(ctx context.Context, t target, n *v1.Namespace, rev int64, wantUID, wantRV, wantPlan string) (int64, *client.NamespacePlan, error) {
	if wantUID != "" && n.UID != wantUID {
		return 0, nil, errf(http.StatusConflict, "Conflict", "namespace %s is another object now (uid %s, not %s): not deleted", t.name, n.UID, wantUID)
	}
	if wantRV != "" && fmt.Sprint(rev) != wantRV {
		return 0, nil, errf(http.StatusConflict, "Conflict", "namespace %s changed since it was read (at %d, not %s): not deleted", t.name, rev, wantRV)
	}
	items, _, err := s.namespaceContents(ctx, t.name)
	if err != nil {
		return 0, nil, err
	}
	plan, err := s.checkCascade(ctx, t.name, items, wantPlan)
	if err != nil {
		return 0, nil, err
	}
	if dryRun(ctx) {
		return 0, plan, nil
	}
	newRev, err := s.writeNamespace(ctx, t.name, rev, func(n *v1.Namespace) {
		if n.Annotations == nil {
			n.Annotations = map[string]string{}
		}
		delete(n.Annotations, client.AnnotationCascadeFailed)
		delete(n.Annotations, client.AnnotationCascadeSince)
		n.Annotations[client.AnnotationCascadeRetry] = cascadeCaller(ctx) + " at " + s.clock.Now().UTC().Format(time.RFC3339Nano)
	})
	return newRev, nil, err
}

// writeNamespace changes namespace name at revision rev, in the store (the finalizer is the
// API's to add: no caller's write could), and returns the revision written.
func (s *Server) writeNamespace(ctx context.Context, name string, rev int64, change func(*v1.Namespace)) (int64, error) {
	k := store.Key{Kind: "Namespace", Name: name}
	cur, err := s.store.Get(ctx, k)
	if err != nil {
		return 0, err
	}
	if cur.Revision != rev {
		return 0, errf(http.StatusConflict, "Conflict", "namespace %s changed while it was being deleted: not deleted; try again", name)
	}
	obj, _, err := v1.Decode(cur.Data)
	if err != nil {
		return 0, err
	}
	n := obj.(*v1.Namespace)
	change(n)
	_, data, err := toMap(n)
	if err != nil {
		return 0, err
	}
	o, err := s.store.Update(ctx, k, data, rev)
	if errors.Is(err, store.ErrConflict) {
		return 0, errf(http.StatusConflict, "Conflict", "namespace %s changed while it was being deleted: not deleted; try again", name)
	}
	return o.Revision, err
}

// cascadeState is where a namespace's cascade is, for a refusal: its step, or why it stopped.
func cascadeState(n *v1.Namespace) string {
	if f := n.Annotations[client.AnnotationCascadeFailed]; f != "" {
		return "stopped: " + f
	}
	if st := n.Annotations[client.AnnotationCascadeStep]; st != "" {
		return st
	}
	return "starting"
}

func cascadeCaller(ctx context.Context) string {
	id, ok := IdentityFrom(ctx)
	if !ok {
		return "anonymous"
	}
	if id == (pki.Identity{}) {
		return "anonymous"
	}
	return id.String()
}
