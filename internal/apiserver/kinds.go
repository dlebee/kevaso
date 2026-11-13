package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/schema"
	"kevaso.com/core/internal/store"
)

// Kinds defined at runtime (design §4.2, ADR 0005). A KindDefinition is a built-in kind; the kinds
// it defines are served here, at /apis/GROUP/VERSION/…, as unstructured objects checked against the
// definition's schema. GET /apis lists every kind served.

// definedKind is one served definition.
type definedKind struct {
	def       *v1.KindDefinition
	res       v1.APIResource
	schema    *schema.Schema
	schemaErr error // a stored definition whose schema no longer compiles: its writes are refused
}

func (d *definedKind) info() v1.KindInfo {
	return v1.KindInfo{Kind: d.res.Resource, Plural: d.res.Resource, Scope: d.res.Scope, HasSpec: true,
		New: func() meta.Object { return &v1.Unstructured{} }}
}

type kindSet struct {
	byPath map[string]*definedKind // GROUP/VERSION/PLURAL
	list   []*definedKind          // by name
}

// kindCache rebuilds the served kinds only when the definitions change.
type kindCache struct {
	mu  sync.Mutex
	fp  string
	set *kindSet
}

// fingerprint names a list of stored objects by their names and revisions.
func fingerprint(objs []store.Object) string {
	var b strings.Builder
	for _, o := range objs {
		fmt.Fprintf(&b, "%s@%d;", o.Key, o.Revision)
	}
	return b.String()
}

func (s *Server) definedKinds(ctx context.Context) (*kindSet, error) {
	objs, _, err := s.store.List(ctx, store.Selector{Kind: "KindDefinition"})
	if err != nil {
		return nil, err
	}
	fp := fingerprint(objs)
	s.kinds.mu.Lock()
	defer s.kinds.mu.Unlock()
	if s.kinds.set != nil && s.kinds.fp == fp {
		return s.kinds.set, nil
	}
	set := &kindSet{byPath: map[string]*definedKind{}}
	for _, o := range objs {
		obj, _, err := v1.Decode(o.Data)
		if err != nil {
			return nil, fmt.Errorf("stored %s: %w", o.Key, err)
		}
		d := obj.(*v1.KindDefinition)
		dk := &definedKind{def: d, res: v1.DefinedResource(d)}
		dk.schema, dk.schemaErr = schema.Compile(d.Spec.Schema)
		set.byPath[d.Spec.APIVersion()+"/"+d.Spec.Names.Plural] = dk
		set.list = append(set.list, dk)
	}
	s.kinds.fp, s.kinds.set = fp, set
	return set, nil
}

// parseAny parses any API path: a built-in kind's, or a defined one's.
func (s *Server) parseAny(ctx context.Context, path string) (target, error) {
	if strings.HasPrefix(path, "/apis/kevaso/v1/") {
		return parsePath(path)
	}
	return s.parseDefined(ctx, path)
}

// parseDefined parses /apis/GROUP/VERSION/[namespaces/NS/]PLURAL[/NAME[/status]].
func (s *Server) parseDefined(ctx context.Context, path string) (target, error) {
	var t target
	rest, ok := strings.CutPrefix(path, "/apis/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if !ok || len(parts) < 3 {
		return t, errf(http.StatusNotFound, "NotFound", "unknown path %q", path)
	}
	gv, parts := parts[0]+"/"+parts[1], parts[2:]
	if len(parts) >= 3 && parts[0] == "namespaces" {
		t.namespace, parts = parts[1], parts[2:]
	}
	set, err := s.definedKinds(ctx)
	if err != nil {
		return t, err
	}
	dk := set.byPath[gv+"/"+parts[0]]
	if dk == nil {
		return t, errf(http.StatusNotFound, "NotFound", "unknown resource %s/%s", gv, parts[0])
	}
	t.kind, t.def = dk.info(), dk
	if dk.res.Scope == v1.Cluster && t.namespace != "" {
		return t, errf(http.StatusNotFound, "NotFound", "%s is cluster-scoped: no namespace in its path", dk.res.Kind)
	}
	if len(parts) >= 2 {
		t.name = parts[1]
	}
	switch {
	case len(parts) == 3 && parts[2] == "status" && dk.res.Status:
		t.status = true
	case len(parts) > 2:
		return t, errf(http.StatusNotFound, "NotFound", "unknown path %q", path)
	}
	return t, nil
}

// registerDefined serves defined kinds and discovery.
func (s *Server) registerDefined() {
	s.mux.HandleFunc("/apis", s.discovery)
	s.mux.HandleFunc("/apis/", s.routeDefined)
}

// discovery lists every kind served: GET /apis.
func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "%s %s", r.Method, r.URL.Path))
		return
	}
	set, err := s.definedKinds(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	var l v1.APIResourceList
	for _, k := range v1.Kinds() {
		l.Resources = append(l.Resources, v1.BuiltinResource(k))
	}
	for _, dk := range set.list {
		l.Resources = append(l.Resources, dk.res)
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) routeDefined(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := s.parseDefined(ctx, r.URL.Path)
	if err != nil {
		writeErr(w, err)
		return
	}
	switch {
	case r.Method == http.MethodGet && t.name == "" && r.URL.Query().Get("watch") == "true":
		s.watch(ctx, w, r, t)
	case r.Method == http.MethodGet && t.name == "":
		s.listDefined(ctx, w, t)
	case r.Method == http.MethodGet:
		s.get(ctx, w, t)
	case r.Method == http.MethodPost && t.name == "" && !t.status:
		s.writeDefined(ctx, w, r, t, s.createDefined, http.StatusCreated)
	case r.Method == http.MethodPut && t.name != "":
		s.writeDefined(ctx, w, r, t, s.updateDefined, http.StatusOK)
	case r.Method == http.MethodDelete && t.name != "" && !t.status:
		s.delete(ctx, w, t)
	default:
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "%s %s", r.Method, r.URL.Path))
	}
}

func (s *Server) listDefined(ctx context.Context, w http.ResponseWriter, t target) {
	objs, rev, err := s.store.List(ctx, store.Selector{Kind: t.kind.Kind, Namespace: t.namespace})
	if err != nil {
		writeErr(w, err)
		return
	}
	l := List{APIVersion: t.def.res.APIVersion(), Kind: t.def.res.Kind + "List", Metadata: ListMeta{ResourceVersion: strconv.FormatInt(rev, 10)}, Items: []json.RawMessage{}}
	for _, o := range objs {
		b, err := render(o)
		if err != nil {
			writeErr(w, err)
			return
		}
		l.Items = append(l.Items, b)
	}
	writeJSON(w, http.StatusOK, l)
}

// decodeDefined reads a defined object: its type must be the path's, its metadata decodes as
// strictly as a built-in's, and the rest is plain JSON for the schema to check.
func decodeDefined(body []byte, dk *definedKind) (*v1.Unstructured, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, errf(http.StatusBadRequest, "BadRequest", "body: %v", err)
	}
	u := &v1.Unstructured{Fields: map[string]any{}}
	for k, v := range raw {
		var err error
		switch k {
		case "apiVersion":
			err = json.Unmarshal(v, &u.APIVersion)
		case "kind":
			err = json.Unmarshal(v, &u.Kind)
		case "metadata":
			dec := json.NewDecoder(bytes.NewReader(v))
			dec.DisallowUnknownFields()
			err = dec.Decode(&u.ObjectMeta)
		default:
			u.Fields[k], err = v1.DecodeValue(v)
		}
		if err != nil {
			return nil, errf(http.StatusUnprocessableEntity, "Invalid", "%s: %s: %v", dk.res.Kind, k, err)
		}
	}
	if u.APIVersion != dk.res.APIVersion() || u.Kind != dk.res.Kind {
		return nil, errf(http.StatusBadRequest, "BadRequest", "body is %s %s, path is %s %s", u.APIVersion, u.Kind, dk.res.APIVersion(), dk.res.Kind)
	}
	return u, nil
}

type definedWrite func(ctx context.Context, t target, u *v1.Unstructured) (store.Object, error)

func (s *Server) writeDefined(ctx context.Context, w http.ResponseWriter, r *http.Request, t target, fn definedWrite, okCode int) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	u, err := decodeDefined(body, t.def)
	if err != nil {
		writeErr(w, err)
		return
	}
	if t.def.schemaErr != nil {
		writeErr(w, errf(http.StatusUnprocessableEntity, "Invalid", "KindDefinition %s: its schema doesn't compile (%v): fix the definition", t.def.def.Name, t.def.schemaErr))
		return
	}
	om := &u.ObjectMeta
	if t.kind.Scope == v1.Namespaced {
		if om.Namespace == "" {
			om.Namespace = t.namespace
		}
		if t.namespace == "" || om.Namespace != t.namespace {
			writeErr(w, errf(http.StatusBadRequest, "BadRequest", "metadata.namespace %q doesn't match the path's namespace %q", om.Namespace, t.namespace))
			return
		}
	} else if om.Namespace != "" {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "%s is cluster-scoped: metadata.namespace must be empty", t.def.res.Kind))
		return
	}
	if t.name != "" && om.Name != t.name {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "metadata.name %q doesn't match the path's name %q", om.Name, t.name))
		return
	}
	if err := meta.ValidateName(om.Name); err != nil {
		writeErr(w, errf(http.StatusUnprocessableEntity, "Invalid", "%s", err))
		return
	}
	t.name = om.Name
	o, err := fn(ctx, t, u)
	if err != nil {
		writeErr(w, err)
		return
	}
	if o.Data == nil { // finalized away
		writeJSON(w, http.StatusOK, Status{Code: http.StatusOK, Reason: "Deleted", Message: t.key().String() + " deleted"})
		return
	}
	b, err := render(o)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, okCode, b)
}

// part is which fields a write covers.
func (t target) part() schema.Part {
	switch {
	case !t.def.res.Status:
		return schema.All
	case t.status:
		return schema.Status
	}
	return schema.Main
}

func (s *Server) createDefined(ctx context.Context, t target, u *v1.Unstructured) (store.Object, error) {
	if t.kind.Scope == v1.Namespaced {
		if _, err := s.store.Get(ctx, store.Key{Kind: "Namespace", Name: t.namespace}); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return store.Object{}, errf(http.StatusNotFound, "NotFound", "namespace %q doesn't exist", t.namespace)
			}
			return store.Object{}, err
		}
	}
	now := s.clock.Now().UTC().Truncate(time.Second)
	om := &u.ObjectMeta
	om.UID, om.CreationTimestamp, om.DeletionTimestamp, om.Generation = newUID(), &now, nil, 1
	if t.def.res.Status { // controllers write status, through /status
		delete(u.Fields, "status")
	}
	if err := s.prepareDefined(ctx, t, nil, u); err != nil {
		return store.Object{}, err
	}
	data, err := s.admitDefined(ctx, t, nil, u)
	if err != nil {
		return store.Object{}, err
	}
	return s.store.Create(ctx, t.key(), data)
}

func (s *Server) updateDefined(ctx context.Context, t target, u *v1.Unstructured) (store.Object, error) {
	if u.ResourceVersion == "" {
		return store.Object{}, errf(http.StatusBadRequest, "BadRequest", "metadata.resourceVersion is required on update (read the object first)")
	}
	expected, err := strconv.ParseInt(u.ResourceVersion, 10, 64)
	if err != nil {
		return store.Object{}, errf(http.StatusBadRequest, "BadRequest", "metadata.resourceVersion %q", u.ResourceVersion)
	}
	cur, err := s.store.Get(ctx, t.key())
	if err != nil {
		return store.Object{}, err
	}
	oldObj, _, err := v1.Decode(cur.Data)
	if err != nil {
		return store.Object{}, err
	}
	old := oldObj.(*v1.Unstructured)
	var next *v1.Unstructured
	if t.status {
		// /status: everything from the stored object but status.
		next, err = v1.ToUnstructured(old)
		if err != nil {
			return store.Object{}, err
		}
		if st, ok := u.Fields["status"]; ok {
			next.Fields["status"] = st
		} else {
			delete(next.Fields, "status")
		}
	} else {
		next = u
		if t.def.res.Status { // status is the controllers': keep it
			if st, ok := old.Fields["status"]; ok {
				next.Fields["status"] = st
			} else {
				delete(next.Fields, "status")
			}
		}
		nm, om := &next.ObjectMeta, &old.ObjectMeta
		nm.UID, nm.CreationTimestamp, nm.DeletionTimestamp = om.UID, om.CreationTimestamp, om.DeletionTimestamp
		if om.DeletionTimestamp != nil {
			if len(nm.Finalizers) == 0 {
				d, err := s.store.Delete(ctx, t.key(), expected)
				return store.Object{Key: d.Key}, err
			}
			if !isSubset(nm.Finalizers, om.Finalizers) {
				return store.Object{}, errf(http.StatusUnprocessableEntity, "Invalid", "%s is being deleted: finalizers can only be removed", t.key())
			}
		}
		if err := s.prepareDefined(ctx, t, old, next); err != nil {
			return store.Object{}, err
		}
		nm.Generation = om.Generation
		if !reflect.DeepEqual(specPart(old), specPart(next)) {
			nm.Generation++
		}
	}
	data, err := s.admitDefined(ctx, t, old, next)
	if err != nil {
		return store.Object{}, err
	}
	return s.store.Update(ctx, t.key(), data, expected)
}

// specPart is what bumps generation: every field but metadata and status.
func specPart(u *v1.Unstructured) map[string]any {
	out := map[string]any{}
	for k, v := range u.Fields {
		if k != "status" {
			out[k] = v
		}
	}
	return out
}

// prepareDefined fills in defaults, then runs mutation policies (not on /status writes).
func (s *Server) prepareDefined(ctx context.Context, t target, old, u *v1.Unstructured) error {
	t.def.schema.Default(u.Fields, t.part())
	if t.status {
		return nil
	}
	set, err := s.policySet(ctx)
	if err != nil {
		return err
	}
	req := s.admissionRequest(ctx, t, old == nil, t.def.res.Kind)
	if !set.Applies(req) {
		return nil
	}
	m, oldM, err := unstructuredMaps(u, old)
	if err != nil {
		return err
	}
	changed, err := set.Mutate(req, m, oldM)
	if err != nil {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s", err)
	}
	if !changed {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var mutated v1.Unstructured
	if err := json.Unmarshal(b, &mutated); err != nil {
		return err
	}
	u.Fields, u.Labels, u.Annotations = mutated.Fields, mutated.Labels, mutated.Annotations
	t.def.schema.Default(u.Fields, t.part()) // a mutation may have made an object with defaults inside
	return nil
}

func unstructuredMaps(u, old *v1.Unstructured) (map[string]any, map[string]any, error) {
	m, _, err := toMap(u)
	if err != nil {
		return nil, nil, err
	}
	var oldM map[string]any
	if old != nil {
		if oldM, _, err = toMap(old); err != nil {
			return nil, nil, err
		}
	}
	return m, oldM, nil
}

// admitDefined checks the object against its definition's schema and rules, then the validation
// policies, and returns what to store.
func (s *Server) admitDefined(ctx context.Context, t target, old, u *v1.Unstructured) ([]byte, error) {
	u.ResourceVersion = ""
	b, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	v, err := v1.DecodeValue(b) // integers stay integers, for the schema's types
	if err != nil {
		return nil, err
	}
	full := v.(map[string]any)
	fields := map[string]any{}
	for k, v := range full {
		if k != "apiVersion" && k != "kind" && k != "metadata" {
			fields[k] = v
		}
	}
	failed := t.def.schema.Validate(fields, full, t.part())
	if !t.status && len(failed) == 0 {
		pf, err := s.validatePolicies(ctx, t, old, full, t.def.res.Kind)
		if err != nil {
			return nil, err
		}
		failed = pf
	}
	if len(failed) > 0 {
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: %s", t.def.res.Kind, u.Name, joinMessages(failed))
	}
	return b, nil
}

// ── KindDefinitions themselves ───────────────────────────────────────────────

var subdomainRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// validateObjectName: names are DNS labels, but a KindDefinition's is PLURAL.GROUP.
func validateObjectName(k v1.KindInfo, name string) error {
	if k.Kind == "KindDefinition" {
		if len(name) == 0 || len(name) > 253 || !subdomainRE.MatchString(name) {
			return fmt.Errorf("name %q: a KindDefinition is named PLURAL.GROUP (databases.acme.dev)", name)
		}
		return nil
	}
	return meta.ValidateName(name)
}

// checkDefinition refuses a definition with bad names, a bad schema, or changes to what can't change.
func (s *Server) checkDefinition(ctx context.Context, d, old *v1.KindDefinition) error {
	set, err := s.definedKinds(ctx)
	if err != nil {
		return err
	}
	others := make([]*v1.KindDefinition, 0, len(set.list))
	for _, dk := range set.list {
		others = append(others, dk.def)
	}
	if errs := schema.CheckDefinition(d, old, others); len(errs) > 0 {
		return errf(http.StatusUnprocessableEntity, "Invalid", "KindDefinition %s: %s", d.Name, joinMessages(errs))
	}
	return nil
}

// checkDeleteDefinition refuses to delete a definition while objects of its kind exist.
func (s *Server) checkDeleteDefinition(ctx context.Context, t target) error {
	if t.kind.Kind != "KindDefinition" {
		return nil
	}
	cur, err := s.store.Get(ctx, t.key())
	if err != nil {
		return err
	}
	obj, _, err := v1.Decode(cur.Data)
	if err != nil {
		return err
	}
	d := obj.(*v1.KindDefinition)
	left, _, err := s.store.List(ctx, store.Selector{Kind: d.Spec.Resource()})
	if err != nil {
		return err
	}
	if n := len(left); n > 0 {
		names := make([]string, 0, min(n, 3))
		for _, o := range left[:min(n, 3)] {
			names = append(names, o.String())
		}
		return errf(http.StatusConflict, "Conflict", "KindDefinition %s still has %d object(s) (%s%s): delete them first",
			d.Name, n, strings.Join(names, ", "), map[bool]string{true: ", …", false: ""}[n > 3])
	}
	return nil
}
