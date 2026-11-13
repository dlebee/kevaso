package schema

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// JSONPath is the small JSONPath subset printer columns use: .field, ["key"], [N], and a filter
// [?(@.field=="value")] that picks the first matching item of a list.
type JSONPath []step

type step struct {
	field  string
	index  int // -1: not an index
	filter []string
	value  string // the filter's value
}

// ParseJSONPath parses a printer column's path, e.g. .status.conditions[?(@.type=="Ready")].status.
func ParseJSONPath(p string) (JSONPath, error) {
	if !strings.HasPrefix(p, ".") {
		return nil, fmt.Errorf("%q: starts with a dot (.spec.size)", p)
	}
	var out JSONPath
	rest := p
	for rest != "" {
		switch {
		case strings.HasPrefix(rest, "."):
			rest = rest[1:]
			end := strings.IndexAny(rest, ".[")
			if end < 0 {
				end = len(rest)
			}
			if end == 0 {
				return nil, fmt.Errorf("%q: empty field name", p)
			}
			out = append(out, step{field: rest[:end], index: -1})
			rest = rest[end:]
		case strings.HasPrefix(rest, "[?(@."):
			end := strings.Index(rest, ")]")
			if end < 0 {
				return nil, fmt.Errorf("%q: unclosed filter", p)
			}
			body := rest[len("[?(@."):end]
			f, v, ok := strings.Cut(body, "==")
			if !ok {
				return nil, fmt.Errorf("%q: a filter is [?(@.field==\"value\")]", p)
			}
			val, err := strconv.Unquote(strings.ReplaceAll(strings.TrimSpace(v), "'", `"`))
			if err != nil {
				return nil, fmt.Errorf("%q: the filter's value is a quoted string", p)
			}
			out = append(out, step{filter: strings.Split(strings.TrimSpace(f), "."), value: val, index: -1})
			rest = rest[end+2:]
		case strings.HasPrefix(rest, "["):
			end := strings.Index(rest, "]")
			if end < 0 {
				return nil, fmt.Errorf("%q: unclosed [", p)
			}
			in := rest[1:end]
			if n, err := strconv.Atoi(in); err == nil && n >= 0 {
				out = append(out, step{index: n})
			} else if k, err := strconv.Unquote(strings.ReplaceAll(in, "'", `"`)); err == nil {
				out = append(out, step{field: k, index: -1})
			} else {
				return nil, fmt.Errorf("%q: [%s]: want an index or a quoted key", p, in)
			}
			rest = rest[end+1:]
		default:
			return nil, fmt.Errorf("%q: unexpected %q", p, rest)
		}
	}
	return out, nil
}

// Find returns the value the path points at in obj.
func (p JSONPath) Find(obj any) (any, bool) {
	cur := obj
	for _, s := range p {
		switch {
		case s.filter != nil:
			l, ok := cur.([]any)
			if !ok {
				return nil, false
			}
			found := false
			for _, e := range l {
				v, ok := JSONPath(fieldSteps(s.filter)).Find(e)
				if str, isStr := v.(string); ok && isStr && str == s.value {
					cur, found = e, true
					break
				}
			}
			if !found {
				return nil, false
			}
		case s.index >= 0:
			l, ok := cur.([]any)
			if !ok || s.index >= len(l) {
				return nil, false
			}
			cur = l[s.index]
		default:
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			if cur, ok = m[s.field]; !ok {
				return nil, false
			}
		}
	}
	return cur, true
}

func fieldSteps(fields []string) []step {
	out := make([]step, len(fields))
	for i, f := range fields {
		out[i] = step{field: f, index: -1}
	}
	return out
}

// Format is a value as a table cell: strings as they are, anything else as JSON, "-" for nothing.
func Format(v any, ok bool) string {
	if !ok || v == nil {
		return "-"
	}
	if s, isStr := v.(string); isStr {
		if s == "" {
			return "-"
		}
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
