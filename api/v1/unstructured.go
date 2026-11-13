package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"

	"kevaso.com/core/api/meta"
)

// Unstructured is an object of a defined kind (ADR 0005): its type, its metadata, and every other
// top-level field (spec, status, …) as plain JSON values: map[string]any, []any, string, bool,
// int64, float64, nil. Integers decode as int64.
//
// Controllers for a defined kind can work with it directly, or convert it to their own Go type
// with Into (and back with ToUnstructured).
type Unstructured struct {
	meta.TypeMeta
	meta.ObjectMeta
	// Fields are the top-level fields other than apiVersion, kind and metadata.
	Fields map[string]any
}

// MarshalJSON writes the object as one JSON object.
func (u *Unstructured) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(u.Fields)+3)
	for k, v := range u.Fields {
		m[k] = v
	}
	m["apiVersion"], m["kind"], m["metadata"] = u.APIVersion, u.Kind, &u.ObjectMeta
	return json.Marshal(m)
}

// UnmarshalJSON reads any JSON object.
func (u *Unstructured) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*u = Unstructured{Fields: map[string]any{}}
	for k, v := range raw {
		var err error
		switch k {
		case "apiVersion":
			err = json.Unmarshal(v, &u.APIVersion)
		case "kind":
			err = json.Unmarshal(v, &u.Kind)
		case "metadata":
			err = json.Unmarshal(v, &u.ObjectMeta)
		default:
			u.Fields[k], err = DecodeValue(v)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	return nil
}

// DecodeValue decodes any JSON value, integers as int64 and other numbers as float64.
func DecodeValue(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return Numbers(v), nil
}

// Numbers turns every json.Number in v into int64 (when integral) or float64, in place for maps and
// slices, and returns v.
func Numbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		f, _ := x.Float64()
		return f
	case float64: // from encoding/json without UseNumber, or from CEL
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return int64(x)
		}
		return x
	case map[string]any:
		for k, e := range x {
			x[k] = Numbers(e)
		}
	case []any:
		for i, e := range x {
			x[i] = Numbers(e)
		}
	}
	return v
}

// Get returns the value at a path of field names (Get("spec", "engine")).
func (u *Unstructured) Get(path ...string) (any, bool) {
	var cur any = u.Fields
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[p]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// GetString returns the string at a path ("" if there's none).
func (u *Unstructured) GetString(path ...string) string {
	v, _ := u.Get(path...)
	s, _ := v.(string)
	return s
}

// GetMap returns the object at a path (nil if there's none).
func (u *Unstructured) GetMap(path ...string) map[string]any {
	v, _ := u.Get(path...)
	m, _ := v.(map[string]any)
	return m
}

// Set sets the value at a path, making the objects on the way.
func (u *Unstructured) Set(value any, path ...string) {
	if len(path) == 0 {
		return
	}
	if u.Fields == nil {
		u.Fields = map[string]any{}
	}
	cur := u.Fields
	for _, p := range path[:len(path)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[path[len(path)-1]] = value
}

// Remove deletes the value at a path, if there is one.
func (u *Unstructured) Remove(path ...string) {
	if len(path) == 0 {
		return
	}
	parent := u.Fields
	if len(path) > 1 {
		parent = u.GetMap(path[:len(path)-1]...)
	}
	delete(parent, path[len(path)-1])
}

// Into converts the object into out (a pointer to a Go type with the same JSON shape).
func (u *Unstructured) Into(out any) error {
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// ToUnstructured converts any object to an Unstructured one.
func ToUnstructured(obj any) (*Unstructured, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	u := &Unstructured{}
	return u, json.Unmarshal(b, u)
}
