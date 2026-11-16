package apiserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

// checkDeleteNamespace refuses to delete a Namespace while it holds any object, of a built-in kind
// or a defined one (audit checkpoint 4), or while anything outside it names it (K-128): its silos
// would run on with no namespace to name them by, and a name used from outside would still match
// whoever is given that name next. The refusal counts what is there per kind and names the first
// few. (Deleting what is in it with the namespace, --cascade, is for later.)
//
// Nothing may slip in between the look and the delete (Rule 3). So the namespace is marked
// Terminating before the look, creates refuse a Terminating namespace and look again once they
// have written (commitInNamespace), a write that newly names one is refused the same way
// (guardNewNames, recheckNewNames), and the delete removes only the namespace as marked: the
// revision returned. A refusal marks it Active again.
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

// creatingIn refuses a new object in a namespace that is being deleted. An update of one that is
// already there still goes through, so a sweep can finish.
func (s *Server) creatingIn(ctx context.Context, ns string) error {
	if ns == "" {
		return nil
	}
	_, err := s.openNamespace(ctx, ns)
	return err
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

// namespaceEmpty is checkDeleteNamespace's look: nil, or the 409 naming what is inside it and what
// outside it still names it.
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
	named, err := s.objectsNaming(ctx, t.name)
	if err != nil {
		return err
	}
	var msgs []string
	if len(in) > 0 {
		parts := make([]string, 0, len(in))
		for _, h := range in {
			parts = append(parts, describeCounted(h.kind, h.names))
		}
		msgs = append(msgs, fmt.Sprintf("namespace %s still holds %s: a namespace is deleted only once it is empty, and deleting it never deletes what is in it. "+
			"Delete those first (kvo delete KIND NAME -n %s; kvo get KIND -n %s lists them), then the namespace",
			t.name, strings.Join(parts, ", "), t.name, t.name))
	}
	if len(named) > 0 {
		msgs = append(msgs, fmt.Sprintf("namespace %s is still named from outside by %s: remove those first, then the namespace",
			t.name, describeRefs(named)))
	}
	if len(msgs) == 0 {
		return nil
	}
	return errf(http.StatusConflict, "Conflict", "%s", strings.Join(msgs, " "))
}

// namespaceNamingKinds are the built-in kinds that can name a namespace other than their own.
// A Grant, a Service and an Ingress do not: a grant's secrets and keys, a service's selector and
// an ingress rule's service are names in that object's own namespace. An allowFrom entry without
// a slash is too, and so is a service-account subject with an empty namespace (it is the binding's).
var namespaceNamingKinds = []string{
	"ClusterRoleBinding", "IngressClass", "MutationPolicy", "Plugin",
	"RoleBinding", "Silo", "SiloSet", "ValidationPolicy",
}

// refHit is one object that names a namespace, for the refusal.
type refHit struct {
	kind, namespace, name string
}

// objectsNaming lists every object outside ns that names it, sorted by kind then namespace/name.
func (s *Server) objectsNaming(ctx context.Context, ns string) ([]refHit, error) {
	var hits []refHit
	for _, kind := range namespaceNamingKinds {
		objs, _, err := s.store.List(ctx, store.Selector{Kind: kind})
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			obj, _, err := v1.Decode(o.Data)
			if err != nil {
				return nil, err
			}
			if !slices.Contains(namespacesNamed(obj), ns) {
				continue
			}
			hits = append(hits, refHit{kind: kind, namespace: o.Namespace, name: o.Name})
		}
	}
	slices.SortFunc(hits, func(a, b refHit) int {
		if c := strings.Compare(a.kind, b.kind); c != 0 {
			return c
		}
		if c := strings.Compare(a.namespace, b.namespace); c != 0 {
			return c
		}
		return strings.Compare(a.name, b.name)
	})
	return hits, nil
}

// namespacesNamed are the namespaces obj names other than its own. Empty when obj names none.
func namespacesNamed(obj meta.Object) []string {
	if obj == nil {
		return nil
	}
	own := obj.GetObjectMeta().Namespace
	seen := map[string]bool{}
	add := func(ns string) {
		if ns != "" && ns != own {
			seen[ns] = true
		}
	}
	switch o := obj.(type) {
	case *v1.RoleBinding:
		subjectNamespaces(add, own, o.Subjects)
	case *v1.ClusterRoleBinding:
		subjectNamespaces(add, own, o.Subjects)
	case *v1.Silo:
		allowFromNamespaces(add, o.Spec.Service)
	case *v1.SiloSet:
		allowFromNamespaces(add, o.Spec.Template.Service)
	case *v1.IngressClass:
		add(o.Spec.Controller.Namespace)
	case *v1.Plugin:
		for _, r := range o.Spec.Owns {
			add(r.Namespace)
		}
	case *v1.ValidationPolicy:
		for _, ns := range o.Spec.Match.Namespaces {
			add(ns)
		}
	case *v1.MutationPolicy:
		for _, ns := range o.Spec.Match.Namespaces {
			add(ns)
		}
	}
	out := make([]string, 0, len(seen))
	for ns := range seen {
		out = append(out, ns)
	}
	slices.Sort(out)
	return out
}

// subjectNamespaces adds the namespaces of service-account subjects. An empty namespace is the
// binding's own (own), which add then drops.
func subjectNamespaces(add func(string), own string, subs []v1.Subject) {
	for _, s := range subs {
		if s.Kind != "ServiceAccount" {
			continue
		}
		ns := s.Namespace
		if ns == "" {
			ns = own
		}
		add(ns)
	}
}

// allowFromNamespaces adds namespaces from NAMESPACE/NAME entries. A name with no slash is a silo
// in the object's own namespace.
func allowFromNamespaces(add func(string), sv *v1.SiloService) {
	if sv == nil {
		return
	}
	for _, p := range sv.Ports {
		for _, a := range p.AllowFrom {
			if ns, _, ok := strings.Cut(a, "/"); ok {
				add(ns)
			}
		}
	}
}

// describeCounted is "N Kind (a, b, c)" or, past three names, "N Kind (a, b, c, …)".
func describeCounted(kind string, names []string) string {
	const shown = 3
	listed := strings.Join(names[:min(len(names), shown)], ", ")
	if len(names) > shown {
		listed += ", …"
	}
	return fmt.Sprintf("%d %s (%s)", len(names), kind, listed)
}

// describeRefs groups hits by kind (they arrive sorted) and describes each group.
func describeRefs(hits []refHit) string {
	var parts []string
	for i := 0; i < len(hits); {
		j := i + 1
		for j < len(hits) && hits[j].kind == hits[i].kind {
			j++
		}
		names := make([]string, 0, j-i)
		for _, h := range hits[i:j] {
			names = append(names, objectID(h.namespace, h.name))
		}
		parts = append(parts, describeCounted(hits[i].kind, names))
		i = j
	}
	return strings.Join(parts, ", ")
}

func objectID(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}

// namedNS is a namespace a write newly names, and the UID it had when the write was checked.
type namedNS struct {
	name, uid string
}

// guardNewNames refuses a write that newly names a namespace being deleted, and returns the ones
// it does name that exist and are not, so recheckNewNames can look again after the write. A
// namespace that does not exist yet is not one of them: naming it is allowed, and deleting that
// namespace later sees the object.
func (s *Server) guardNewNames(ctx context.Context, old, next meta.Object) ([]namedNS, error) {
	before := map[string]bool{}
	for _, ns := range namespacesNamed(old) {
		before[ns] = true
	}
	var out []namedNS
	for _, ns := range namespacesNamed(next) {
		if before[ns] {
			continue
		}
		o, err := s.store.Get(ctx, store.Key{Kind: "Namespace", Name: ns})
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		obj, _, err := v1.Decode(o.Data)
		if err != nil {
			return nil, err
		}
		n := obj.(*v1.Namespace)
		if n.Status.Phase == "Terminating" {
			return nil, errf(http.StatusConflict, "Conflict", "namespace %s is being deleted: nothing new can name it", ns)
		}
		out = append(out, namedNS{name: ns, uid: n.UID})
	}
	return out, nil
}

// recheckNewNames is guardNewNames' second look, after the write: the namespace was marked,
// deleted or made again in between. The caller undoes the write.
func (s *Server) recheckNewNames(ctx context.Context, seen []namedNS) error {
	for _, w := range seen {
		now, err := s.openNamespace(ctx, w.name)
		if err != nil || now != w.uid {
			return errf(http.StatusConflict, "Conflict", "namespace %s is being deleted: nothing new can name it", w.name)
		}
	}
	return nil
}
