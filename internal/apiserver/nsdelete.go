package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

// checkDeleteNamespace refuses to delete a Namespace while it holds any object, of a built-in kind
// or a defined one (audit checkpoint 4), unless the delete asks for the cascade (?cascade=true,
// nscascade.go), or while anything outside it names it (K-128): its silos would run on with no
// namespace to name them by, and a name used from outside would still match whoever is given that
// name next. The refusal counts what is there per kind and names the first few.
//
// Nothing may slip in between the look and the delete (Rule 3). So the namespace is marked
// Terminating before the look, creates refuse a Terminating namespace and look again once they
// have written (commitInNamespace), a write that newly names one is refused the same way
// (guardNewNames, recheckNewNames), and the delete removes only the namespace as marked: the
// revision returned. A refusal marks it Active again.
//
// wantUID and wantRV are the delete's ?uid= and ?resourceVersion=, checked here against the
// namespace before it is marked (the mark changes its revision). A dry-run cascade returns the
// plan instead, and deletes nothing.
func (s *Server) checkDeleteNamespace(ctx context.Context, r *http.Request, t target, wantUID, wantRV string) (int64, *client.NamespacePlan, error) {
	if t.kind.Kind != "Namespace" {
		return 0, nil, nil
	}
	q := r.URL.Query()
	cascade := q.Get("cascade") == "true"
	if c := q.Get("cascade"); c != "" && c != "true" && c != "false" {
		return 0, nil, errf(http.StatusBadRequest, "BadRequest", "cascade is true or false, not %q", c)
	}
	cur, err := s.store.Get(ctx, store.Key{Kind: "Namespace", Name: t.name})
	if err != nil {
		return 0, nil, err
	}
	obj, _, err := v1.Decode(cur.Data)
	if err != nil {
		return 0, nil, err
	}
	if n := obj.(*v1.Namespace); slices.Contains(n.Finalizers, client.CascadeFinalizer) {
		if !cascade {
			return 0, nil, errf(http.StatusConflict, "Conflict", "namespace %s is being deleted with what is in it (%s): "+
				"kvo delete namespace %s shows what is left and resumes it (the API: ?cascade=true)", t.name, cascadeState(n), t.name)
		}
		return s.resumeCascade(ctx, t, n, cur.Revision, wantUID, wantRV, q.Get("plan"))
	}
	rev, err := s.markNamespace(ctx, t.name, "Terminating", wantUID, wantRV)
	if err != nil {
		return 0, nil, err
	}
	newRev, plan, err := s.lookBeforeDelete(ctx, t, rev, cascade, q.Get("plan"))
	if err != nil && rev != 0 {
		_, _ = s.markNamespace(ctx, t.name, "Active", "", strconv.FormatInt(rev, 10)) // changed since: whoever changed it decides
	}
	return newRev, plan, err
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

// lookBeforeDelete is checkDeleteNamespace's look, on the namespace marked at rev: the revision the
// delete removes, the plan of a dry-run cascade, or the refusal. Without the cascade, the 409
// naming what is inside it and what outside it still names it. With it, only what outside names
// it is refused (409), and what the caller may not delete (403); otherwise the namespace is marked
// for the cascade (startCascade) and kevasod deletes the rest.
func (s *Server) lookBeforeDelete(ctx context.Context, t target, rev int64, cascade bool, wantPlan string) (int64, *client.NamespacePlan, error) {
	items, labels, err := s.namespaceContents(ctx, t.name)
	if err != nil {
		return 0, nil, err
	}
	named, err := s.objectsNaming(ctx, t.name)
	if err != nil {
		return 0, nil, err
	}
	var msgs []string
	if len(items) > 0 && !cascade {
		msgs = append(msgs, fmt.Sprintf("namespace %s still holds %s: a namespace that holds anything is deleted only with what is in it, when asked to. "+
			"kvo delete namespace %s lists it all and asks first (the API: ?cascade=true); or delete those yourself (kvo delete KIND NAME -n %s; kvo get KIND -n %s lists them), then the namespace",
			t.name, describeHeld(items, labels), t.name, t.name, t.name))
	}
	if len(named) > 0 {
		msgs = append(msgs, fmt.Sprintf("namespace %s is still named from outside by %s: remove those first, then the namespace",
			t.name, describeRefs(named)))
	}
	if len(msgs) > 0 {
		return 0, nil, errf(http.StatusConflict, "Conflict", "%s", strings.Join(msgs, " "))
	}
	if !cascade {
		return rev, nil, nil
	}
	plan, err := s.checkCascade(ctx, t.name, items, wantPlan)
	if err != nil {
		return 0, nil, err
	}
	if dryRun(ctx) {
		return 0, plan, nil
	}
	if len(items) == 0 {
		return rev, nil, nil // nothing in it: deleted as any empty namespace is
	}
	newRev, err := s.startCascade(ctx, t.name, rev)
	return newRev, nil, err
}

// namespaceContents is everything in namespace ns, of every namespaced kind the API knows, and
// how the 409 names each kind (a defined kind as "Kind (resource)").
func (s *Server) namespaceContents(ctx context.Context, ns string) ([]client.CascadeItem, map[string]string, error) {
	var items []client.CascadeItem
	labels := map[string]string{}
	add := func(kind, label string, objs []store.Object) error {
		for _, o := range objs {
			var m struct {
				Metadata meta.ObjectMeta `json:"metadata"`
				Spec     struct {
					Volumes []json.RawMessage `json:"volumes"`
				} `json:"spec"`
			}
			if err := json.Unmarshal(o.Data, &m); err != nil {
				return fmt.Errorf("%s/%s/%s: %w", kind, ns, o.Name, err)
			}
			it := client.CascadeItem{Kind: kind, Name: o.Name, UID: m.Metadata.UID, Deleting: m.Metadata.DeletionTimestamp != nil}
			if kind == "Silo" {
				it.Disks = len(m.Spec.Volumes)
			}
			items = append(items, it)
		}
		labels[kind] = label
		return nil
	}
	for _, k := range v1.Kinds() {
		if k.Scope != v1.Namespaced {
			continue
		}
		kind := k.Kind // an API kind, stored under its name
		objs, _, err := s.store.List(ctx, store.Selector{Kind: kind, Namespace: ns})
		if err != nil {
			return nil, nil, err
		}
		if err := add(kind, kind, objs); err != nil {
			return nil, nil, err
		}
	}
	set, err := s.definedKinds(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, dk := range set.list {
		if dk.res.Scope != v1.Namespaced {
			continue
		}
		d := dk.def // a defined kind, stored under PLURAL.GROUP
		res := d.Spec.Resource()
		objs, _, err := s.store.List(ctx, store.Selector{Kind: d.Spec.Resource(), Namespace: ns})
		if err != nil {
			return nil, nil, err
		}
		if err := add(res, dk.res.Kind+" ("+dk.res.Resource+")", objs); err != nil {
			return nil, nil, err
		}
	}
	return items, labels, nil
}

// describeHeld is the 409's "N Kind (a, b, c)" per kind, in the order the API lists kinds.
func describeHeld(items []client.CascadeItem, labels map[string]string) string {
	var parts []string
	for i := 0; i < len(items); {
		j := i
		var names []string
		for j < len(items) && items[j].Kind == items[i].Kind {
			names = append(names, items[j].Name)
			j++
		}
		parts = append(parts, describeCounted(labels[items[i].Kind], names))
		i = j
	}
	return strings.Join(parts, ", ")
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
		allowFromNamespaces(add, o.Spec.Services)
	case *v1.SiloSet:
		allowFromNamespaces(add, o.Spec.Template.Services)
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

// subjectNamespaces adds the namespaces a binding's subjects name. A service account's empty
// namespace is the binding's own (own), which add then drops. A group subject
// system:serviceaccounts:NS is that namespace too: a service account's token carries the group,
// so the binding still applies after the namespace is created again under the same name.
func subjectNamespaces(add func(string), own string, subs []v1.Subject) {
	for _, s := range subs {
		switch s.Kind {
		case "ServiceAccount":
			ns := s.Namespace
			if ns == "" {
				ns = own
			}
			add(ns)
		case "Group":
			if ns, ok := strings.CutPrefix(s.Name, "system:serviceaccounts:"); ok { // the namespace a service-account token's group names
				add(ns)
			}
		}
	}
}

// allowFromNamespaces adds namespaces from NAMESPACE/NAME entries. A name with no slash is a silo
// in the object's own namespace.
func allowFromNamespaces(add func(string), svs []v1.SiloService) {
	for _, sv := range svs {
		for _, p := range sv.Ports {
			for _, a := range p.AllowFrom {
				if ns, _, ok := strings.Cut(a, "/"); ok {
					add(ns)
				}
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
