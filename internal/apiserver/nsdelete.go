package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

// checkDeleteNamespace refuses to delete a Namespace while it holds any object, of a built-in kind
// or a defined one (audit checkpoint 4): its silos would run on with no namespace to name them by,
// and nothing would ever delete them. The refusal counts what is there per kind and names the
// first few. (Deleting what is in it with the namespace, --cascade, is for later.)
func (s *Server) checkDeleteNamespace(ctx context.Context, t target) error {
	if t.kind.Kind != "Namespace" {
		return nil
	}
	type held struct {
		kind  string
		names []string
	}
	var in []held
	look := func(kind, storeKind string) error {
		objs, _, err := s.store.List(ctx, store.Selector{Kind: storeKind, Namespace: t.name})
		if err != nil {
			return err
		}
		if len(objs) == 0 {
			return nil
		}
		h := held{kind: kind}
		for _, o := range objs {
			h.names = append(h.names, o.Key.Name)
		}
		in = append(in, h)
		return nil
	}
	for _, k := range v1.Kinds() {
		if k.Scope != v1.Namespaced {
			continue
		}
		if err := look(k.Kind, k.Kind); err != nil {
			return err
		}
	}
	set, err := s.definedKinds(ctx)
	if err != nil {
		return err
	}
	for _, dk := range set.list {
		if dk.res.Scope != v1.Namespaced {
			continue
		}
		if err := look(dk.res.Kind+" ("+dk.res.Resource+")", dk.def.Spec.Resource()); err != nil {
			return err
		}
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
