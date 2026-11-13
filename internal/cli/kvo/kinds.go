package kvo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/schema"
)

// Kinds defined at runtime (ADR 0005): kvo learns them from the server (GET /apis). Inside kvo, a
// defined kind's KindInfo.Kind is its resource, PLURAL.GROUP, which the client resolves; built-in
// kind names never have a dot.

func isDefined(k v1.KindInfo) bool { return strings.Contains(k.Kind, ".") }

// resolveKind finds a kind by name: built-in first, then what the server defines.
func resolveKind(ctx context.Context, c *client.Client, name string) (v1.KindInfo, error) {
	k, err := kindOf(name)
	if err == nil {
		return k, nil
	}
	r, rerr := c.Resolve(ctx, name)
	if rerr != nil {
		if strings.HasPrefix(rerr.Error(), "unknown kind") {
			return v1.KindInfo{}, err // the built-in error lists what's known
		}
		return v1.KindInfo{}, rerr
	}
	return definedInfo(r), nil
}

func definedInfo(r v1.APIResource) v1.KindInfo {
	if r.BuiltIn {
		k, _ := v1.Lookup(r.Kind)
		return k
	}
	return v1.KindInfo{Kind: r.Resource, Plural: r.Resource, Scope: r.Scope, HasSpec: true, ShortNames: r.ShortNames,
		New: func() meta.Object { return &v1.Unstructured{} }}
}

// objectKind is the KindInfo of a decoded object (from apply), defined kinds included.
func objectKind(ctx context.Context, c *client.Client, obj meta.Object, k v1.KindInfo) (v1.KindInfo, error) {
	if _, ok := obj.(*v1.Unstructured); !ok {
		return k, nil
	}
	tm := obj.GetTypeMeta()
	r, err := c.ResolveObject(ctx, tm.APIVersion, tm.Kind)
	if err != nil {
		return v1.KindInfo{}, err
	}
	return definedInfo(r), nil
}

// getKinds is `kvo get kinds`: every kind the cluster serves.
func getKinds(ctx context.Context, c *client.Client, stdout io.Writer) error {
	rs, err := c.Resources(ctx)
	if err != nil {
		return err
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].BuiltIn != rs[j].BuiltIn {
			return rs[i].BuiltIn
		}
		return rs[i].Resource < rs[j].Resource
	})
	tw := tabwriter.NewWriter(stdout, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tSHORTNAMES\tAPIVERSION\tKIND\tSCOPE\tSTATUS")
	for _, r := range rs {
		st := "-"
		if r.Status && !r.BuiltIn {
			st = "subresource"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Resource, dash(strings.Join(r.ShortNames, ",")), r.APIVersion(), r.Kind, r.Scope, st)
	}
	return tw.Flush()
}

// printDefinedTable is `kvo get` for a defined kind: NAME, the definition's printer columns, AGE.
func printDefinedTable(ctx context.Context, c *client.Client, w io.Writer, k v1.KindInfo, objs []meta.Object, all bool) error {
	r, err := c.Resolve(ctx, k.Kind)
	if err != nil {
		return err
	}
	type col struct {
		name string
		path schema.JSONPath
	}
	var cols []col
	for _, pc := range r.PrinterColumns {
		p, err := schema.ParseJSONPath(pc.JSONPath)
		if err != nil {
			continue // the server checked it; a newer syntax shows as nothing rather than failing
		}
		cols = append(cols, col{strings.ToUpper(pc.Name), p})
	}
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	var head []string
	if all && k.Scope == v1.Namespaced {
		head = append(head, "NAMESPACE")
	}
	head = append(head, "NAME")
	for _, c := range cols {
		head = append(head, c.name)
	}
	head = append(head, "AGE")
	_, _ = fmt.Fprintln(tw, strings.Join(head, "\t"))
	sort.Slice(objs, func(i, j int) bool {
		a, b := objs[i].GetObjectMeta(), objs[j].GetObjectMeta()
		return a.Namespace+"/"+a.Name < b.Namespace+"/"+b.Name
	})
	for _, obj := range objs {
		m := obj.GetObjectMeta()
		var row []string
		if all && k.Scope == v1.Namespaced {
			row = append(row, m.Namespace)
		}
		row = append(row, m.Name)
		if len(cols) > 0 {
			whole, err := asMap(obj)
			if err != nil {
				return err
			}
			for _, c := range cols {
				v, ok := c.path.Find(whole)
				row = append(row, schema.Format(v, ok))
			}
		}
		row = append(row, age(m))
		_, _ = fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

func asMap(obj meta.Object) (map[string]any, error) {
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

// unstructuredConditions reads status.conditions of a defined object, if it has the usual shape.
func unstructuredConditions(u *v1.Unstructured) []meta.Condition {
	raw, ok := u.Get("status", "conditions")
	if !ok {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var conds []meta.Condition
	if json.Unmarshal(b, &conds) != nil {
		return nil
	}
	return conds
}

// describeFields lists a defined object's fields (spec, status, …) for describe, as indented YAML.
func describeFields(u *v1.Unstructured) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(u.Fields)) {
		var buf strings.Builder
		if err := printYAML(&buf, []meta.Object{&fieldDoc{u.Fields[k]}}); err != nil {
			continue
		}
		lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
		out = append(out, strings.ToUpper(k[:1])+k[1:]+":")
		for _, l := range lines {
			out = append(out, "  "+l)
		}
	}
	return out
}

// fieldDoc lets printYAML print one value.
type fieldDoc struct{ v any }

func (f *fieldDoc) GetTypeMeta() *meta.TypeMeta     { return &meta.TypeMeta{} }
func (f *fieldDoc) GetObjectMeta() *meta.ObjectMeta { return &meta.ObjectMeta{} }
func (f *fieldDoc) MarshalJSON() ([]byte, error)    { return json.Marshal(f.v) }
