package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sync"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/admission"
	"kevaso.com/core/internal/store"
)

// Admission policies (design §4.1, ADR 0005): after defaults, MutationPolicies set fields; after the
// kind's own checks, ValidationPolicies may refuse. Built-in and defined kinds alike; never the
// policies' own kinds or RBAC, never /status writes or deletes.

// policyCache recompiles the policies only when they change.
type policyCache struct {
	mu  sync.Mutex
	fp  string
	set *admission.Set
}

func (s *Server) policySet(ctx context.Context) (*admission.Set, error) {
	vobjs, _, err := s.store.List(ctx, store.Selector{Kind: "ValidationPolicy"})
	if err != nil {
		return nil, err
	}
	mobjs, _, err := s.store.List(ctx, store.Selector{Kind: "MutationPolicy"})
	if err != nil {
		return nil, err
	}
	fp := fingerprint(vobjs) + "|" + fingerprint(mobjs)
	s.policies.mu.Lock()
	defer s.policies.mu.Unlock()
	if s.policies.set != nil && s.policies.fp == fp {
		return s.policies.set, nil
	}
	var vps []*v1.ValidationPolicy
	var mps []*v1.MutationPolicy
	for _, o := range append(vobjs, mobjs...) {
		obj, _, err := v1.Decode(o.Data)
		if err != nil {
			return nil, fmt.Errorf("stored %s: %w (policies fail closed)", o.Key, err)
		}
		switch p := obj.(type) {
		case *v1.ValidationPolicy:
			vps = append(vps, p)
		case *v1.MutationPolicy:
			mps = append(mps, p)
		}
	}
	s.policies.fp, s.policies.set = fp, admission.Compile(vps, mps)
	return s.policies.set, nil
}

// admissionRequest describes a write for policies. kind is the object's kind (Silo, Database).
func (s *Server) admissionRequest(ctx context.Context, t target, create bool, kind string) admission.Request {
	r := admission.Request{Operation: v1.OperationUpdate, Verb: "update", Namespace: t.namespace, Name: t.name,
		Kind: kind, Resource: t.kind.Plural, BuiltIn: t.def == nil, Groups: GroupsFrom(ctx)}
	if create {
		r.Operation, r.Verb = v1.OperationCreate, "create"
	}
	if id, ok := IdentityFrom(ctx); ok {
		r.User = id.Name
	}
	return r
}

func (s *Server) validatePolicies(ctx context.Context, t target, old meta.Object, obj map[string]any, kind string) ([]string, error) {
	set, err := s.policySet(ctx)
	if err != nil {
		return nil, err
	}
	req := s.admissionRequest(ctx, t, isNil(old), kind)
	if !set.Applies(req) {
		return nil, nil
	}
	var oldM map[string]any
	if !isNil(old) {
		if oldM, _, err = toMap(old); err != nil {
			return nil, err
		}
	}
	return set.Validate(req, obj, oldM), nil
}

func isNil(o meta.Object) bool {
	return o == nil || reflect.ValueOf(o).IsNil()
}

// admitBuiltin is admit for a built-in kind's create or update, with what's new in M17 around it:
// checks of KindDefinitions and policies themselves, mutation policies first, then the built-in
// guards (guards.go) on the object as mutated, the kind's rules, and validation policies last.
// old is nil on create.
func (s *Server) admitBuiltin(ctx context.Context, t target, old, obj meta.Object) ([]byte, error) {
	switch o := obj.(type) {
	case *v1.KindDefinition:
		prev, _ := old.(*v1.KindDefinition)
		if err := s.checkDefinition(ctx, o, prev); err != nil {
			return nil, err
		}
	case *v1.ValidationPolicy:
		if err := admission.CheckValidationPolicy(o); err != nil {
			return nil, errf(http.StatusUnprocessableEntity, "Invalid", "ValidationPolicy %s: %v", o.Name, err)
		}
	case *v1.MutationPolicy:
		if err := admission.CheckMutationPolicy(o); err != nil {
			return nil, errf(http.StatusUnprocessableEntity, "Invalid", "MutationPolicy %s: %v", o.Name, err)
		}
	}
	if t.status {
		return s.admit(t.kind.Kind, obj)
	}
	set, err := s.policySet(ctx)
	if err != nil {
		return nil, err
	}
	req := s.admissionRequest(ctx, t, isNil(old), t.kind.Kind)
	if !set.Applies(req) {
		if err := s.guard(ctx, t, obj); err != nil {
			return nil, err
		}
		return s.admit(t.kind.Kind, obj)
	}
	before := privileges(obj)
	if obj, err = s.mutateBuiltin(ctx, t, req, old, obj); err != nil {
		return nil, err
	}
	if err := checkMutatedSecretValue(obj); err != nil {
		return nil, err
	}
	if err := s.checkMutatedPrivileges(ctx, t, before, obj); err != nil {
		return nil, err
	}
	if err := s.guard(ctx, t, obj); err != nil { // on the object as mutated: policies can't get past them
		return nil, err
	}
	data, err := s.admit(t.kind.Kind, obj)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if failed, err := s.validatePolicies(ctx, t, old, m, t.kind.Kind); err != nil {
		return nil, err
	} else if len(failed) > 0 {
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: %s", t.kind.Kind, obj.GetObjectMeta().Name, joinMessages(failed))
	}
	return data, nil
}

// mutateBuiltin runs mutation policies on a built-in object; what comes out must still decode
// strictly into the kind's Go type.
func (s *Server) mutateBuiltin(ctx context.Context, t target, req admission.Request, old, obj meta.Object) (meta.Object, error) {
	set, err := s.policySet(ctx)
	if err != nil {
		return nil, err
	}
	m, _, err := toMap(obj)
	if err != nil {
		return nil, err
	}
	var oldM map[string]any
	if !isNil(old) {
		if oldM, _, err = toMap(old); err != nil {
			return nil, err
		}
	}
	changed, err := set.Mutate(req, m, oldM)
	if err != nil {
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "%s", err)
	}
	if !changed {
		return obj, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	next := t.kind.New()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(next); err != nil {
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: after mutation policies: %v (a policy set a field this kind doesn't have)", t.kind.Kind, obj.GetObjectMeta().Name, err)
	}
	if !isNil(old) && t.kind.HasSpec { // generation follows the spec as mutated
		nm, om := next.GetObjectMeta(), old.GetObjectMeta()
		nm.Generation = om.Generation
		if !reflect.DeepEqual(getField(old, "Spec"), getField(next, "Spec")) {
			nm.Generation++
		}
	}
	return next, nil
}
