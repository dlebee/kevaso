package apiserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

// checkDeleteNamespace refuses to delete a Namespace while it holds any object, of a built-in kind
// or a defined one (audit checkpoint 4): its silos would run on with no namespace to name them by,
// and nothing would ever delete them. The refusal counts what is there per kind and names the
// first few. (Deleting what is in it with the namespace, --cascade, is for later.)
//
// Nothing may slip in between the look and the delete (Rule 3: whoever gets a namespace of that
// name next would get it). So the namespace is marked Terminating before the look, creates refuse
// a Terminating namespace and look again once they have written (commitInNamespace), and the
// delete removes only the namespace as marked: the revision returned. A refusal marks it Active
// again.
//
// wantUID and wantRV are the delete's ?uid= and ?resourceVersion=, checked here against the
// namespace before it is marked (the mark changes its revision).
func (s *Server) checkDeleteNamespace(ctx context.Context, t target, wantUID, wantRV string) (int64, error) {
	if t.kind.Kind != "Namespace" {
		return 0, nil
	}
	rev, err := s.markNamespace(ctx, t.name, "Terminating", wantUID, wantRV)
	if err != nil {
		return 0, err
	}
	err = s.namespaceEmpty(ctx, t)
	if err != nil && rev != 0 {
		_, _ = s.markNamespace(ctx, t.name, "Active", "", strconv.FormatInt(rev, 10)) // changed since: whoever changed it decides
	}
	return rev, err
}

// markNamespace sets a namespace's phase, if it is still the one with UID wantUID at revision
// wantRV (each "": any), and returns the revision it is then at; 0 on a dry run, which marks
// nothing.
func (s *Server) markNamespace(ctx context.Context, name, phase, wantUID, wantRV string) (int64, error) {
	k := store.Key{Kind: "Namespace", Name: name}
	for attempt := 0; attempt < 5; attempt++ {
		cur, err := s.store.Get(ctx, k)
		if err != nil {
			return 0, err
		}
		obj, _, err := v1.Decode(cur.Data)
		if err != nil {
			return 0, err
		}
		n := obj.(*v1.Namespace)
		if wantUID != "" && n.UID != wantUID {
			return 0, errf(http.StatusConflict, "Conflict", "%s is another object now (uid %s, not %s): not deleted", k, n.UID, wantUID)
		}
		if wantRV != "" && strconv.FormatInt(cur.Revision, 10) != wantRV {
			return 0, errf(http.StatusConflict, "Conflict", "%s changed since it was read (at %d, not %s): not deleted", k, cur.Revision, wantRV)
		}
		if dryRun(ctx) {
			return 0, nil
		}
		if n.Status.Phase == phase {
			return cur.Revision, nil
		}
		n.Status.Phase = phase
		_, data, err := toMap(n)
		if err != nil {
			return 0, err
		}
		o, err := s.store.Update(ctx, k, data, cur.Revision)
		if errors.Is(err, store.ErrConflict) && wantRV == "" {
			continue
		}
		return o.Revision, err
	}
	return 0, errf(http.StatusConflict, "Conflict", "namespace %s keeps changing: not deleted; try again", name)
}

// openNamespace is the UID of the namespace that a create in it writes into: 404 when there is
// none, 409 while it is being deleted.
func (s *Server) openNamespace(ctx context.Context, name string) (string, error) {
	o, err := s.store.Get(ctx, store.Key{Kind: "Namespace", Name: name})
	if errors.Is(err, store.ErrNotFound) {
		return "", errf(http.StatusNotFound, "NotFound", "namespace %q doesn't exist", name)
	}
	if err != nil {
		return "", err
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return "", err
	}
	n := obj.(*v1.Namespace)
	if n.Status.Phase == "Terminating" {
		return "", errf(http.StatusConflict, "Conflict", "namespace %s is being deleted: nothing new can be made in it", name)
	}
	return n.UID, nil
}

// commitInNamespace creates a namespaced object in the namespace whose UID is uid (openNamespace),
// then looks at the namespace again: if it has since been marked for deletion, deleted or made
// again, the object is taken back out and the create refused. With the mark checkDeleteNamespace
// sets before its look, either that look sees the object or this one sees the mark.
func (s *Server) commitInNamespace(ctx context.Context, t target, uid string, data []byte) (store.Object, error) {
	o, err := s.commitCreate(ctx, t.key(), data)
	if err != nil || dryRun(ctx) {
		return o, err
	}
	now, err := s.openNamespace(ctx, t.namespace)
	if err == nil && now == uid {
		return o, nil
	}
	if err == nil {
		err = errf(http.StatusNotFound, "NotFound", "namespace %q doesn't exist", t.namespace)
	}
	if _, derr := s.store.Delete(ctx, t.key(), o.Revision); derr != nil && !errors.Is(derr, store.ErrNotFound) {
		return store.Object{}, fmt.Errorf("%s was written as namespace %s was deleted, and taking it back out failed: %w", t.key(), t.namespace, derr)
	}
	return store.Object{}, err
}

// namespaceEmpty is checkDeleteNamespace's look: nil, or the 409 naming what is there.
func (s *Server) namespaceEmpty(ctx context.Context, t target) error {
	type held struct {
		kind  string
		names []string
	}
	var in []held
	note := func(kind string, objs []store.Object) {
		if len(objs) == 0 {
			return
		}
		h := held{kind: kind}
		for _, o := range objs {
			h.names = append(h.names, o.Name)
		}
		in = append(in, h)
	}
	for _, k := range v1.Kinds() {
		if k.Scope != v1.Namespaced {
			continue
		}
		kind := k.Kind // an API kind, stored under its name
		objs, _, err := s.store.List(ctx, store.Selector{Kind: kind, Namespace: t.name})
		if err != nil {
			return err
		}
		note(kind, objs)
	}
	set, err := s.definedKinds(ctx)
	if err != nil {
		return err
	}
	for _, dk := range set.list {
		if dk.res.Scope != v1.Namespaced {
			continue
		}
		d := dk.def // a defined kind, stored under PLURAL.GROUP
		objs, _, err := s.store.List(ctx, store.Selector{Kind: d.Spec.Resource(), Namespace: t.name})
		if err != nil {
			return err
		}
		note(dk.res.Kind+" ("+dk.res.Resource+")", objs)
	}
	if len(in) == 0 {
		return nil
	}
	const shown = 3
	parts := make([]string, 0, len(in))
	for _, h := range in {
		names := strings.Join(h.names[:min(len(h.names), shown)], ", ")
		if len(h.names) > shown {
			names += ", …"
		}
		parts = append(parts, fmt.Sprintf("%d %s (%s)", len(h.names), h.kind, names))
	}
	return errf(http.StatusConflict, "Conflict", "namespace %s still holds %s: a namespace is deleted only once it is empty, and deleting it never deletes what is in it. "+
		"Delete those first (kvo delete KIND NAME -n %s; kvo get KIND -n %s lists them), then the namespace",
		t.name, strings.Join(parts, ", "), t.name, t.name)
}
