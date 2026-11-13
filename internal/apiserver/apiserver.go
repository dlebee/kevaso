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
	"slices"
	"strconv"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/approvals"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/leases"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/rbac"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"

	"github.com/hashicorp/yamux"
)

// Server is the API server.
type Server struct {
	store store.Store
	clock clock.Clock
	valid *validator
	mux   *http.ServeMux
	auth  *Auth
	h     http.Handler

	tunnels  tunnels // agents' dial-out connections, by host
	policy   *rbac.Source
	vault    *secrets.Vault // nil: no KMS, secrets can't hold values
	kmsAdmin KMSAdmin
	backup   func(context.Context, []byte) ([]byte, error)
	joinNode SystemNodeJoiner // POST /join/system-node (systemnodes.go)

	approvalLimits approvals.Limits
	leaseLimits    leases.Limits                     // port leases (leases.go)
	classes        func() map[string]scheduler.Class // the plugins' classes; nil: none
	paneRates      paneRates

	kinds    kindCache   // the served KindDefinitions (kinds.go)
	policies policyCache // the admission policies (policies.go)
}

// New returns a server over a store, without authentication (kevasod dev, tests).
func New(s store.Store, c clock.Clock) (*Server, error) { return NewWithAuth(s, c, nil) }

// NewWithAuth returns a server that authenticates every request (see Auth).
func NewWithAuth(s store.Store, c clock.Clock, auth *Auth) (*Server, error) {
	v, err := newValidator(builtinRules)
	if err != nil {
		return nil, err
	}
	srv := &Server{store: s, clock: c, valid: v, mux: http.NewServeMux(), auth: auth, approvalLimits: approvals.Limits{}.WithDefaults()}
	srv.tunnels.sess = map[string]*yamux.Session{}
	srv.policy = &rbac.Source{Store: s}
	if auth != nil {
		if err := srv.ensureBuiltins(context.Background()); err != nil {
			return nil, err
		}
	}
	srv.mux.HandleFunc("/apis/kevaso/v1/", srv.route)
	srv.registerDefined()
	srv.mux.HandleFunc("/agent/connect", srv.agentConnect)
	srv.mux.HandleFunc(client.PathAgentBroker, srv.agentBroker)
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
	exec      bool   // a silo's /exec
	token     bool   // a service account's /token
	value     bool   // a secret's /value
	move      bool   // a silo's /move
	answer    string // an approval's /approve or /deny
	bundle    bool   // a pane's /bundle
	stream    string // a silo's /ssh or /files (silostreams.go)
	lease     string // a silo's /open or /close (leases.go)

	def   *definedKind // a kind defined by a KindDefinition (kinds.go); nil for built-ins
	scale bool         // a defined kind's /scale (scale.go)
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
	case len(parts) == 3 && parts[2] == "exec" && k.Kind == "Silo":
		t.exec = true
	case len(parts) == 3 && (parts[2] == "ssh" || parts[2] == "files") && k.Kind == "Silo":
		t.stream = parts[2]
	case len(parts) == 3 && parts[2] == "move" && k.Kind == "Silo":
		t.move = true
	case len(parts) == 3 && (parts[2] == "open" || parts[2] == "close") && k.Kind == "Silo":
		t.lease = parts[2]
	case len(parts) == 3 && parts[2] == "token" && k.Kind == "ServiceAccount":
		t.token = true
	case len(parts) == 3 && parts[2] == "value" && k.Kind == "Secret":
		t.value = true
	case len(parts) == 3 && parts[2] == "bundle" && k.Kind == "Pane":
		t.bundle = true
	case len(parts) == 3 && (parts[2] == "approve" || parts[2] == "deny") && k.Kind == "Approval":
		t.answer = parts[2]
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
	case t.exec:
		s.siloExec(w, r, t.namespace, t.name)
	case t.stream == "ssh":
		s.siloSSH(w, r, t.namespace, t.name)
	case t.stream == "files":
		s.siloFiles(w, r, t.namespace, t.name)
	case t.move:
		s.moveSilo(w, r, t)
	case t.lease != "":
		s.siloLease(w, r, t)
	case t.token:
		s.serviceAccountToken(w, r, t)
	case t.value && r.Method == http.MethodGet:
		s.secretValue(ctx, w, t)
	case t.answer != "":
		s.answerApproval(w, r, t)
	case t.bundle:
		s.paneBundle(w, r, t)
	case t.kind.Kind == "Approval" && (r.Method == http.MethodPost || r.Method == http.MethodPut) && !internal(ctx):
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "approvals are made by the broker when a silo asks; answer one with kvo approve or kvo deny"))
	case t.kind.Kind == "Lease" && (r.Method == http.MethodPost || r.Method == http.MethodPut) && !internal(ctx):
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "leases are made when a silo or a person asks; use kvo open / kvo close"))
	case t.kind.Kind == "Pane" && (r.Method == http.MethodPost || r.Method == http.MethodPut) && !internal(ctx):
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "panes are reported by their silo (spec.panes); they can't be written through the API"))
	case t.value:
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "%s %s: set a value with an update of the secret", r.Method, r.URL.Path))
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
	if filter, _ := ctx.Value(nsFilterKey).(bool); filter {
		id, _ := IdentityFrom(ctx)
		p, err := s.policy.Policy(ctx)
		if err != nil {
			writeErr(w, err)
			return
		}
		mine := p.NamespacesFor(rbac.Attributes{User: id.Name, Groups: GroupsFrom(ctx)})
		objs = slices.DeleteFunc(objs, func(o store.Object) bool { return !slices.Contains(mine, o.Name) })
	}
	if filter, _ := ctx.Value(secretFilterKey).(bool); filter {
		objs = slices.DeleteFunc(objs, func(o store.Object) bool { return !s.visibleSecret(ctx, o) })
	}
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
	filterSecrets, _ := ctx.Value(secretFilterKey).(bool)
	for ev := range ch {
		if filterSecrets && !s.visibleSecret(ctx, ev.Object) {
			continue
		}
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
	ctx = withDryRun(ctx, r) // dryrun.go
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
	if err := validateObjectName(t.kind, om.Name); err != nil {
		writeErr(w, errf(http.StatusUnprocessableEntity, "Invalid", "%s", err))
		return
	}
	t.name = om.Name
	// The guards (exposure, secrets, runtime fit, …) run in admitBuiltin, on the object as stored.
	value, err := s.prepareSecret(ctx, t, obj)
	if err != nil {
		writeErr(w, err)
		return
	}
	o, err := fn(ctx, t, obj)
	if err != nil {
		clear(value)
		writeErr(w, err)
		return
	}
	if value != nil && o.Data != nil && !dryRun(ctx) {
		if o, err = s.storeSecretValue(ctx, o, value); err != nil {
			writeErr(w, err)
			return
		}
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
	failed := append(s.valid.validate(kind, m), semantic(obj)...)
	if set, ok := obj.(*v1.SiloSet); ok {
		// Its instances must be valid silos: say so now, not when the first one is made.
		inst := set.Instance(0, false)
		if im, _, err := toMap(inst); err == nil {
			for _, f := range append(s.valid.validate("Silo", im), semantic(inst)...) {
				failed = append(failed, "template: "+f)
			}
		}
	}
	if len(failed) > 0 {
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
	data, err := s.admitBuiltin(ctx, t, nil, obj)
	if err != nil {
		return store.Object{}, err
	}
	return s.commitCreate(ctx, t.key(), data)
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

	if id, ok := IdentityFrom(ctx); ok && id.Type == "host" && id.Role == "worker" && t.kind.Kind == "Silo" {
		// A host writes from its own copy: a stale one is a conflict to retry on fresh data, not
		// a refusal (what it may write is judged against the stored status below).
		if cur.Revision != expected {
			return store.Object{}, errf(http.StatusConflict, "Conflict", "%s: %v", t.key(), store.ErrConflict)
		}
		if err := moves.HostWrite(old.(*v1.Silo).Status, obj.(*v1.Silo).Status, id.Name); err != nil {
			return store.Object{}, errf(http.StatusForbidden, "Forbidden", "%v", err)
		}
	}
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
				d, err := s.commitDelete(ctx, t.key(), expected)
				return store.Object{Key: d.Key}, err // no Data: tells write() the object is gone
			}
			if !isSubset(nm.Finalizers, oldMeta.Finalizers) {
				return store.Object{}, errf(http.StatusUnprocessableEntity, "Invalid", "%s is being deleted: finalizers can only be removed", t.key())
			}
		}
	}
	next.GetObjectMeta().ResourceVersion = om.ResourceVersion
	data, err := s.admitBuiltin(ctx, t, old, next) // transition: a guard, after mutation policies
	if err != nil {
		return store.Object{}, err
	}
	return s.commitUpdate(ctx, t.key(), data, expected)
}

// delete removes an object, or, while it has finalizers, marks it as being deleted and leaves the
// rest to the controllers that own the finalizers.
func (s *Server) delete(ctx context.Context, w http.ResponseWriter, t target) {
	if err := s.checkDeleteDefinition(ctx, t); err != nil {
		writeErr(w, err)
		return
	}
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
			if t.kind.Kind == "Secret" && s.vault != nil {
				s.vault.Forget(ctx, t.namespace, t.name)
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

// ensureBuiltins creates the built-in roles and the cluster-admins binding if they're missing.
// (Changing them is allowed; deleting one brings it back on the next start.)
func (s *Server) ensureBuiltins(ctx context.Context) error {
	var objs []meta.Object
	for _, r := range rbac.BuiltinRoles() {
		objs = append(objs, r)
	}
	for _, b := range rbac.BuiltinBindings() {
		objs = append(objs, b)
	}
	for _, o := range objs {
		k, _ := v1.Lookup(o.GetTypeMeta().Kind)
		_, err := s.create(ctx, target{kind: k, name: o.GetObjectMeta().Name}, o)
		if err != nil && !errors.Is(err, store.ErrExists) {
			return fmt.Errorf("built-in %s %s: %w", k.Kind, o.GetObjectMeta().Name, err)
		}
	}
	return nil
}

// checkExposure: making silos reachable from outside is its own permission, create on
// services/expose-public in the namespace (design §7.2a), on top of writing the object: a silo
// exposed with hostPort or loadBalancer, a SiloSet whose instances would be (its controller makes
// them, so the check is here), and a Service of type LoadBalancer. Status writes don't change the
// spec, so they don't need it.
func (s *Server) checkExposure(ctx context.Context, t target, obj meta.Object) error {
	if t.status || s.auth == nil {
		return nil
	}
	how := exposure(obj)
	if how == "" {
		return nil
	}
	if old, err := s.store.Get(ctx, t.key()); err == nil { // already exposed the same way: nothing new
		if prev, _, err := v1.Decode(old.Data); err == nil && exposure(prev) == how {
			return nil
		}
	}
	id, _ := IdentityFrom(ctx)
	if id == LocalAdmin || id == Component || id.Type == "host" {
		return nil
	}
	p, err := s.policy.Policy(ctx)
	if err != nil {
		return err
	}
	d := p.Authorize(rbac.Attributes{User: id.Name, Groups: GroupsFrom(ctx), Verb: "create", Resource: "services/expose-public", Namespace: t.namespace})
	if !d.Allowed {
		return errf(http.StatusForbidden, "Forbidden", "%s may not expose silos publicly (needs create on services/expose-public): %s", id, d.Reason)
	}
	return nil
}

// exposure is how an object makes silos reachable from outside ("" if it doesn't).
func exposure(obj meta.Object) string {
	var svc *v1.SiloService
	switch o := obj.(type) {
	case *v1.Silo:
		svc = o.Spec.Service
	case *v1.SiloSet:
		svc = o.Spec.Template.Service
	case *v1.Service:
		if o.Spec.Type == v1.ServiceLoadBalancer {
			return "service:" + o.Spec.LoadBalancerClass
		}
		return ""
	}
	if svc == nil || (svc.Expose != v1.ExposeHostPort && svc.Expose != v1.ExposeLoadBalancer) {
		return ""
	}
	return svc.Expose
}
