package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/schema"
	"kevaso.com/core/internal/store"
)

// The scale subresource of defined kinds (ADR 0005 §10b): GET …/NAME/scale reads the object's
// replica counts as a Scale; PUT sets the wanted one, as an update of the object's main resource
// (defaults, mutation policies, schema, rules and validation policies all apply). RBAC calls it
// PLURAL.GROUP/scale.

func (s *Server) serveScale(ctx context.Context, w http.ResponseWriter, r *http.Request, t target) {
	if t.name == "" {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "%s: scale is per object", r.URL.Path))
		return
	}
	switch r.Method {
	case http.MethodGet:
		cur, err := s.store.Get(ctx, t.key())
		if err != nil {
			writeErr(w, err)
			return
		}
		sc, err := s.scaleOf(t, cur)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, sc)
	case http.MethodPut:
		ctx = withDryRun(ctx, r)
		body, err := readBody(r)
		if err != nil {
			writeErr(w, err)
			return
		}
		var in v1.Scale
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			writeErr(w, errf(http.StatusUnprocessableEntity, "Invalid", "Scale: %v", err))
			return
		}
		if in.Name != "" && in.Name != t.name {
			writeErr(w, errf(http.StatusBadRequest, "BadRequest", "metadata.name %q doesn't match the path's name %q", in.Name, t.name))
			return
		}
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
		u, err := v1.ToUnstructured(obj)
		if err != nil {
			writeErr(w, err)
			return
		}
		segs, _ := schema.FieldPath(t.def.def.Spec.Subresources.Scale.SpecReplicasPath) // checked with the definition
		schema.SetInt(u.Fields, segs, in.Spec.Replicas)
		u.ResourceVersion = in.ResourceVersion
		if u.ResourceVersion == "" { // no resourceVersion: scale whatever is stored now
			u.ResourceVersion = strconv.FormatInt(cur.Revision, 10)
		}
		main := t
		main.scale = false
		o, err := s.updateDefined(ctx, main, u)
		if err != nil {
			writeErr(w, err)
			return
		}
		sc, err := s.scaleOf(t, o)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, sc)
	default:
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "%s %s: GET or PUT a Scale", r.Method, r.URL.Path))
	}
}

// scaleOf is a stored object's Scale.
func (s *Server) scaleOf(t target, o store.Object) (*v1.Scale, error) {
	v, err := v1.DecodeValue(o.Data)
	if err != nil {
		return nil, err
	}
	full, _ := v.(map[string]any)
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return nil, err
	}
	om := obj.GetObjectMeta()
	sc := &v1.Scale{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Scale"},
		ObjectMeta: meta.ObjectMeta{Name: om.Name, Namespace: om.Namespace, UID: om.UID, CreationTimestamp: om.CreationTimestamp,
			ResourceVersion: strconv.FormatInt(o.Revision, 10)}}
	paths := t.def.def.Spec.Subresources.Scale
	if segs, err := schema.FieldPath(paths.SpecReplicasPath); err == nil {
		sc.Spec.Replicas, _ = schema.GetInt(full, segs)
	}
	if segs, err := schema.FieldPath(paths.StatusReplicasPath); err == nil {
		sc.Status.Replicas, _ = schema.GetInt(full, segs)
	}
	return sc, nil
}

// plainOf is an object as plain JSON values (integers as int64), as the schema sees it.
func plainOf(obj meta.Object) (map[string]any, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	v, err := v1.DecodeValue(b)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

// withoutTypeAndMeta is an object's fields other than apiVersion, kind and metadata.
func withoutTypeAndMeta(full map[string]any) map[string]any {
	fields := map[string]any{}
	for k, v := range full {
		if k != "apiVersion" && k != "kind" && k != "metadata" {
			fields[k] = v
		}
	}
	return fields
}
