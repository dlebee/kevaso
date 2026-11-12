// Package apiserver serves the Kevaso API over HTTP, Kubernetes-style:
//
//	/apis/kevaso/v1/{plural}                                  cluster-scoped kinds; all namespaces
//	/apis/kevaso/v1/namespaces/{ns}/{plural}[/{name}[/status]] namespaced kinds
//
// Every write goes through the same pipeline: decode strictly into the Go type (unknown fields and
// wrong types are refused) → defaults (namespace, uid, timestamps, generation) → name rules →
// CEL rules → store with optimistic concurrency. A list with ?watch=true streams events as JSON
// lines, resuming from ?resourceVersion=N.
//
// M1 has no authentication: it's served on loopback for development. M2 adds TLS and the admin
// socket, M4 OIDC and RBAC.
package apiserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// Server is the API server.
type Server struct {
	store store.Store
	clock clock.Clock
	valid *validator
	mux   *http.ServeMux
	auth  *Auth
	h     http.Handler
}

// New returns a server over a store, without authentication (kevasod dev, tests).
func New(s store.Store, c clock.Clock) (*Server, error) { return NewWithAuth(s, c, nil) }

// NewWithAuth returns a server that authenticates every request (see Auth).
func NewWithAuth(s store.Store, c clock.Clock, auth *Auth) (*Server, error) {
	v, err := newValidator(builtinRules)
	if err != nil {
		return nil, err
	}
	srv := &Server{store: s, clock: c, valid: v, mux: http.NewServeMux(), auth: auth}
	srv.mux.HandleFunc("/apis/kevaso/v1/", srv.route)
	srv.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	srv.h = srv.wrap(srv.mux)
	return srv, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.h.ServeHTTP(w, r) }

// Status is the error body, like Kubernetes' Status.
type Status struct {
	Code    int    `json:"code"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

type apiError struct {
	code   int
	reason string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func errf(code int, reason, format string, args ...any) error {
	return &apiError{code: code, reason: reason, msg: fmt.Sprintf(format, args...)}
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
	case errors.Is(err, store.ErrNotFound):
		ae = &apiError{http.StatusNotFound, "NotFound", err.Error()}
	case errors.Is(err, store.ErrExists):
		ae = &apiError{http.StatusConflict, "AlreadyExists", err.Error()}
	case errors.Is(err, store.ErrConflict):
		ae = &apiError{http.StatusConflict, "Conflict", err.Error()}
	case errors.Is(err, store.ErrCompacted):
		ae = &apiError{http.StatusGone, "Expired", err.Error()}
	default:
		ae = &apiError{http.StatusInternalServerError, "InternalError", err.Error()}
	}
	writeJSON(w, ae.code, Status{Code: ae.code, Reason: ae.reason, Message: ae.msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// target is what a request path names.
type target struct {
	kind      v1.KindInfo
	namespace string
	name      string
	status    bool
}

func parsePath(path string) (target, error) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/apis/kevaso/v1/"), "/"), "/")
	var t target
	if len(parts) >= 2 && parts[0] == "namespaces" && len(parts) >= 3 {
		t.namespace, parts = parts[1], parts[2:]
	}
	if len(parts) == 0 || parts[0] == "" {
		return t, errf(http.StatusNotFound, "NotFound", "no kind in path %q", path)
	}
	k, ok := v1.Lookup(parts[0])
	if !ok || parts[0] != k.Plural {
		return t, errf(http.StatusNotFound, "NotFound", "unknown resource %q", parts[0])
	}
	t.kind = k
	if k.Scope == v1.Cluster && t.namespace != "" {
		return t, errf(http.StatusNotFound, "NotFound", "%s is cluster-scoped: no namespace in its path", k.Kind)
	}
	if len(parts) >= 2 {
		t.name = parts[1]
	}
	switch {
	case len(parts) == 3 && parts[2] == "status":
		t.status = true
	case len(parts) > 2:
		return t, errf(http.StatusNotFound, "NotFound", "unknown path %q", path)
	}
	return t, nil
}

func (t target) key() store.Key {
	return store.Key{Kind: t.kind.Kind, Namespace: t.namespace, Name: t.name}
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	t, err := parsePath(r.URL.Path)
	if err != nil {
		writeErr(w, err)
		return
	}
	ctx := r.Context()
	switch {
	case r.Method == http.MethodGet && t.name == "" && r.URL.Query().Get("watch") == "true":
		s.watch(ctx, w, r, t)
	case r.Method == http.MethodGet && t.name == "":
		s.list(ctx, w, t)
	case r.Method == http.MethodGet:
		s.get(ctx, w, t)
	case r.Method == http.MethodPost && t.name == "":
		s.write(ctx, w, r, t, s.create, http.StatusCreated)
	case r.Method == http.MethodPut && t.name != "":
		s.write(ctx, w, r, t, s.update, http.StatusOK)
	case r.Method == http.MethodDelete && t.name != "":
		s.delete(ctx, w, t)
	default:
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "%s %s", r.Method, r.URL.Path))
	}
}

// ── reading ──────────────────────────────────────────────────────────────────

// render turns a stored object into its API form: the stored JSON with metadata.resourceVersion set.
func render(o store.Object) (json.RawMessage, error) {
	var m map[string]any
	if err := json.Unmarshal(o.Data, &m); err != nil {
		return nil, err
	}
	md, _ := m["metadata"].(map[string]any)
	if md == nil {
		md = map[string]any{}
		m["metadata"] = md
	}
	md["resourceVersion"] = strconv.FormatInt(o.Revision, 10)
	return json.Marshal(m)
}

func (s *Server) get(ctx context.Context, w http.ResponseWriter, t target) {
	o, err := s.store.Get(ctx, t.key())
	if err != nil {
		writeErr(w, err)
		return
	}
	b, err := render(o)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// List is the body of a list response.
type List struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ListMeta          `json:"metadata"`
	Items      []json.RawMessage `json:"items"`
}

// ListMeta carries the revision to watch from.
type ListMeta struct {
	ResourceVersion string `json:"resourceVersion"`
}

func (s *Server) list(ctx context.Context, w http.ResponseWriter, t target) {
	objs, rev, err := s.store.List(ctx, store.Selector{Kind: t.kind.Kind, Namespace: t.namespace})
	if err != nil {
		writeErr(w, err)
		return
	}
	l := List{APIVersion: v1.APIVersion, Kind: t.kind.Kind + "List", Metadata: ListMeta{ResourceVersion: strconv.FormatInt(rev, 10)}, Items: []json.RawMessage{}}
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

// WatchEvent is one line of a watch stream.
type WatchEvent struct {
	Type   string          `json:"type"` // ADDED | MODIFIED | DELETED
	Object json.RawMessage `json:"object"`
}

func (s *Server) watch(ctx context.Context, w http.ResponseWriter, r *http.Request, t target) {
	var from int64
	if rv := r.URL.Query().Get("resourceVersion"); rv != "" {
		n, err := strconv.ParseInt(rv, 10, 64)
		if err != nil || n < 0 {
			writeErr(w, errf(http.StatusBadRequest, "BadRequest", "resourceVersion %q", rv))
			return
		}
		from = n
	}
	ch, err := s.store.Watch(ctx, store.Selector{Kind: t.kind.Kind, Namespace: t.namespace}, from)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	enc := json.NewEncoder(w)
	for ev := range ch {
		b, err := render(ev.Object)
		if err != nil {
			return
		}
		if enc.Encode(WatchEvent{Type: string(ev.Type), Object: b}) != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// ── writing ──────────────────────────────────────────────────────────────────

type writeFunc func(ctx context.Context, t target, obj meta.Object) (store.Object, error)

func (s *Server) write(ctx context.Context, w http.ResponseWriter, r *http.Request, t target, fn writeFunc, okCode int) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	obj, err := decodeStrict(body, t.kind)
	if err != nil {
		writeErr(w, err)
		return
	}
	om := obj.GetObjectMeta()
	if t.kind.Scope == v1.Namespaced {
		if om.Namespace == "" {
			om.Namespace = t.namespace
		}
		if t.namespace == "" || om.Namespace != t.namespace {
			writeErr(w, errf(http.StatusBadRequest, "BadRequest", "metadata.namespace %q doesn't match the path's namespace %q", om.Namespace, t.namespace))
			return
		}
	} else if om.Namespace != "" {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "%s is cluster-scoped: metadata.namespace must be empty", t.kind.Kind))
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
	o, err := fn(ctx, t, obj)
	if err != nil {
		writeErr(w, err)
		return
	}
	if o.Data == nil { // finalized away: the object is gone
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

func readBody(r *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(http.MaxBytesReader(nil, r.Body, 4<<20)); err != nil {
		return nil, errf(http.StatusRequestEntityTooLarge, "RequestEntityTooLarge", "body: %v", err)
	}
	return buf.Bytes(), nil
}

// decodeStrict decodes into the kind's Go type, refusing unknown fields and wrong types.
func decodeStrict(body []byte, k v1.KindInfo) (meta.Object, error) {
	var tm meta.TypeMeta
	if err := json.Unmarshal(body, &tm); err != nil {
		return nil, errf(http.StatusBadRequest, "BadRequest", "body: %v", err)
	}
	if tm.APIVersion != v1.APIVersion || tm.Kind != k.Kind {
		return nil, errf(http.StatusBadRequest, "BadRequest", "body is %s %s, path is %s %s", tm.APIVersion, tm.Kind, v1.APIVersion, k.Kind)
	}
	obj := k.New()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(obj); err != nil {
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "%s: %v", k.Kind, err)
	}
	return obj, nil
}

// toMap re-encodes the typed object, so CEL sees exactly what will be stored.
func toMap(obj meta.Object) (map[string]any, []byte, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, nil, err
	}
	return m, b, nil
}

func (s *Server) admit(kind string, obj meta.Object) ([]byte, error) {
	obj.GetObjectMeta().ResourceVersion = "" // never stored: it's the store's revision
	m, b, err := toMap(obj)
	if err != nil {
		return nil, err
	}
	if failed := s.valid.validate(kind, m); len(failed) > 0 {
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: %s", kind, obj.GetObjectMeta().Name, joinMessages(failed))
	}
	return b, nil
}

func newUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) create(ctx context.Context, t target, obj meta.Object) (store.Object, error) {
	if t.kind.Scope == v1.Namespaced {
		if _, err := s.store.Get(ctx, store.Key{Kind: "Namespace", Name: t.namespace}); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return store.Object{}, errf(http.StatusNotFound, "NotFound", "namespace %q doesn't exist", t.namespace)
			}
			return store.Object{}, err
		}
	}
	om := obj.GetObjectMeta()
	now := s.clock.Now().UTC().Truncate(time.Second)
	om.UID, om.CreationTimestamp, om.DeletionTimestamp = newUID(), &now, nil
	om.Generation = 1
	if t.kind.Kind == "Namespace" {
		obj.(*v1.Namespace).Status.Phase = "Active"
	}
	data, err := s.admit(t.kind.Kind, obj)
	if err != nil {
		return store.Object{}, err
	}
	return s.store.Create(ctx, t.key(), data)
}

// update replaces an object (or only its status, for /status). It needs the resourceVersion the
// client read: a stale one is a 409 Conflict, so concurrent writers never overwrite each other.
func (s *Server) update(ctx context.Context, t target, obj meta.Object) (store.Object, error) {
	om := obj.GetObjectMeta()
	if om.ResourceVersion == "" {
		return store.Object{}, errf(http.StatusBadRequest, "BadRequest", "metadata.resourceVersion is required on update (read the object first)")
	}
	expected, err := strconv.ParseInt(om.ResourceVersion, 10, 64)
	if err != nil {
		return store.Object{}, errf(http.StatusBadRequest, "BadRequest", "metadata.resourceVersion %q", om.ResourceVersion)
	}
	cur, err := s.store.Get(ctx, t.key())
	if err != nil {
		return store.Object{}, err
	}
	old, _, err := v1.Decode(cur.Data)
	if err != nil {
		return store.Object{}, err
	}
	oldMeta := old.GetObjectMeta()

	var next meta.Object
	if t.status {
		// /status: everything from the stored object except status.
		next = old
		setField(next, "Status", getField(obj, "Status"))
	} else {
		// Main resource: everything from the client except status, and system-owned metadata.
		next = obj
		setField(next, "Status", getField(old, "Status"))
		nm := next.GetObjectMeta()
		nm.UID, nm.CreationTimestamp, nm.DeletionTimestamp = oldMeta.UID, oldMeta.CreationTimestamp, oldMeta.DeletionTimestamp
		nm.Generation = oldMeta.Generation
		if t.kind.HasSpec && !reflect.DeepEqual(getField(old, "Spec"), getField(next, "Spec")) {
			nm.Generation++
		}
		// Once deleting, finalizers may only be removed; when the last one goes, the object goes.
		if oldMeta.DeletionTimestamp != nil {
			if len(nm.Finalizers) == 0 {
				d, err := s.store.Delete(ctx, t.key(), expected)
				return store.Object{Key: d.Key}, err // no Data: tells write() the object is gone
			}
			if !isSubset(nm.Finalizers, oldMeta.Finalizers) {
				return store.Object{}, errf(http.StatusUnprocessableEntity, "Invalid", "%s is being deleted: finalizers can only be removed", t.key())
			}
		}
	}
	next.GetObjectMeta().ResourceVersion = om.ResourceVersion
	data, err := s.admit(t.kind.Kind, next)
	if err != nil {
		return store.Object{}, err
	}
	return s.store.Update(ctx, t.key(), data, expected)
}

// delete removes an object, or, while it has finalizers, marks it as being deleted and leaves the
// rest to the controllers that own the finalizers.
func (s *Server) delete(ctx context.Context, w http.ResponseWriter, t target) {
	for attempt := 0; attempt < 5; attempt++ {
		cur, err := s.store.Get(ctx, t.key())
		if err != nil {
			writeErr(w, err)
			return
		}
		obj, _, err := v1.Decode(cur.Data)
		if err != nil {
			writeErr(w, err)
			return
		}
		om := obj.GetObjectMeta()
		if len(om.Finalizers) == 0 {
			if _, err := s.store.Delete(ctx, t.key(), cur.Revision); errors.Is(err, store.ErrConflict) {
				continue
			} else if err != nil {
				writeErr(w, err)
				return
			}
			writeJSON(w, http.StatusOK, Status{Code: http.StatusOK, Reason: "Deleted", Message: t.key().String() + " deleted"})
			return
		}
		if om.DeletionTimestamp == nil {
			now := s.clock.Now().UTC().Truncate(time.Second)
			om.DeletionTimestamp = &now
			_, data, err := toMap(obj)
			if err != nil {
				writeErr(w, err)
				return
			}
			o, err := s.store.Update(ctx, t.key(), data, cur.Revision)
			if errors.Is(err, store.ErrConflict) {
				continue
			} else if err != nil {
				writeErr(w, err)
				return
			}
			cur = o
		}
		b, err := render(cur)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, b)
		return
	}
	writeErr(w, errf(http.StatusConflict, "Conflict", "%s keeps changing; try again", t.key()))
}

func isSubset(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range b {
		set[x] = true
	}
	for _, x := range a {
		if !set[x] {
			return false
		}
	}
	return true
}

// getField / setField read and write a top-level struct field (Spec, Status) of any kind.
func getField(obj meta.Object, name string) any {
	v := reflect.ValueOf(obj).Elem().FieldByName(name)
	if !v.IsValid() {
		return nil
	}
	return v.Interface()
}

func setField(obj meta.Object, name string, val any) {
	v := reflect.ValueOf(obj).Elem().FieldByName(name)
	if v.IsValid() && val != nil {
		v.Set(reflect.ValueOf(val))
	}
}
