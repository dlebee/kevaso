// Package nsdelete is the order in which a namespace's contents are deleted with it (networking
// v2, "Deleting"), and how what is left is described. The API server plans with it, kevasod's
// namespace controller deletes by it, and kvo delete all follows it.
//
// The order: stop the silos (sets first, so none is made again; a silo's own disks go with it,
// held by its volumes finalizer), remove the load balancers and open ports, release the IPs (sets,
// then the IPs themselves, each releasing its provider address), then everything else, and last
// what the rest may still need while it goes: secrets and who may do what. Every namespaced kind
// the API knows is covered: a kind not named below, built in or defined, is in "the rest".
package nsdelete

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Stage is one step: the kinds it deletes, in order. Each step waits until everything it deleted
// is gone before the next begins.
type Stage struct {
	Name  string
	Kinds []string // nil: every kind no other stage names
}

// Stages are the steps, in order.
var Stages = []Stage{
	{Name: "stop silos", Kinds: []string{"SiloSet", "Silo"}},
	{Name: "remove load balancers", Kinds: []string{"Service", "Ingress", "Lease"}},
	{Name: "release IPs", Kinds: []string{"IPSet", "IP"}},
	{Name: "delete the rest"},
	{Name: "delete secrets and access", Kinds: []string{"Grant", "Secret", "RoleBinding", "Role", "ServiceAccount"}},
}

// rest is the stage of every kind no other stage names.
var rest = slices.IndexFunc(Stages, func(s Stage) bool { return s.Kinds == nil })

// StageNames are the steps' names, in order.
func StageNames() []string {
	out := make([]string, len(Stages))
	for i, s := range Stages {
		out[i] = s.Name
	}
	return out
}

// StageOf is the step that deletes kind, and its place within that step.
func StageOf(kind string) (stage, pos int) {
	for i, s := range Stages {
		if j := slices.Index(s.Kinds, kind); j >= 0 {
			return i, j
		}
	}
	return rest, 0
}

// Sort puts items in the order they are deleted (step, kind's place, kind, name) and sets each
// one's Stage.
func Sort(items []client.CascadeItem) {
	for i := range items {
		items[i].Stage, _ = StageOf(items[i].Kind)
	}
	slices.SortStableFunc(items, func(a, b client.CascadeItem) int {
		sa, pa := StageOf(a.Kind)
		sb, pb := StageOf(b.Kind)
		if sa != sb {
			return sa - sb
		}
		if pa != pb {
			return pa - pb
		}
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
}

// Plan is the dry run's answer for items (sorted first).
func Plan(namespace string, items []client.CascadeItem) *client.NamespacePlan {
	items = slices.Clone(items)
	Sort(items)
	if items == nil {
		items = []client.CascadeItem{}
	}
	return &client.NamespacePlan{Namespace: namespace, Items: items, Summary: Summary(items), ID: PlanID(items), Stages: StageNames()}
}

// PlanID names exactly these objects: the same objects (by UID) give the same ID, anything added,
// removed or made again under a name gives another.
func PlanID(items []client.CascadeItem) string {
	lines := make([]string, 0, len(items))
	for _, it := range items {
		lines = append(lines, it.Kind+"/"+it.Name+"/"+it.UID)
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:8])
}

// Summary describes items by kind, in the order they go: "3 silos (2 with disks), 2 kept IPs,
// 4 secrets". Empty for none.
func Summary(items []client.CascadeItem) string {
	items = slices.Clone(items)
	Sort(items)
	var parts []string
	for i := 0; i < len(items); {
		j, disks := i, 0
		for j < len(items) && items[j].Kind == items[i].Kind {
			if items[j].Disks > 0 {
				disks++
			}
			j++
		}
		p := Count(items[i].Kind, j-i)
		if disks > 0 {
			p += fmt.Sprintf(" (%d with disks)", disks)
		}
		parts = append(parts, p)
		i = j
	}
	return strings.Join(parts, ", ")
}

// Count is "1 silo", "3 silos", "2 kept IPs", "1 widgets.example.com".
func Count(kind string, n int) string {
	one, many := Noun(kind)
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Noun is how kind reads, one and many.
func Noun(kind string) (one, many string) {
	switch kind {
	case "IP":
		return "kept IP", "kept IPs"
	case "IPSet":
		return "IP set", "IP sets"
	case "SiloSet":
		return "silo set", "silo sets"
	case "RoleBinding":
		return "role binding", "role bindings"
	case "ServiceAccount":
		return "service account", "service accounts"
	case "OpenShellPolicy":
		return "OpenShell policy", "OpenShell policies"
	case "VMImage":
		return "VM image", "VM images"
	}
	if k, ok := v1.Lookup(kind); ok {
		return strings.ToLower(k.Kind), k.Plural
	}
	return kind, kind // a defined kind: PLURAL.GROUP
}

// Describe is "3 silos (a, b, c)" per kind, at most three names each: what is left, or refused.
func Describe(items []client.CascadeItem) string {
	items = slices.Clone(items)
	Sort(items)
	var parts []string
	for i := 0; i < len(items); {
		j := i
		var names []string
		for j < len(items) && items[j].Kind == items[i].Kind {
			names = append(names, items[j].Name)
			j++
		}
		listed := strings.Join(names[:min(len(names), 3)], ", ")
		if len(names) > 3 {
			listed += ", …"
		}
		parts = append(parts, Count(items[i].Kind, len(names))+" ("+listed+")")
		i = j
	}
	return strings.Join(parts, ", ")
}

// Next is the first step that still has anything, and what it has; -1 when nothing is left.
func Next(items []client.CascadeItem) (int, []client.CascadeItem) {
	items = slices.Clone(items)
	Sort(items)
	if len(items) == 0 {
		return -1, nil
	}
	st := items[0].Stage
	end := slices.IndexFunc(items, func(it client.CascadeItem) bool { return it.Stage != st })
	if end < 0 {
		end = len(items)
	}
	return st, items[:end]
}

// Contents is what namespace ns holds, of every namespaced kind the API knows, through c.
func Contents(ctx context.Context, c *client.Client, ns string) ([]client.CascadeItem, error) {
	res, err := c.Resources(ctx)
	if err != nil {
		return nil, err
	}
	var items []client.CascadeItem
	for _, r := range res {
		if r.Scope != v1.Namespaced {
			continue
		}
		kind := r.Resource // a defined kind: PLURAL.GROUP
		if r.BuiltIn {
			kind = r.Kind
		}
		l, err := c.List(ctx, kind, ns)
		if client.IsNotFound(err) { // its definition went
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("listing %s in %s: %w", r.Plural, ns, err)
		}
		for _, raw := range l.Items {
			var m struct {
				Metadata meta.ObjectMeta `json:"metadata"`
				Spec     struct {
					Volumes []json.RawMessage `json:"volumes"`
				} `json:"spec"`
			}
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, fmt.Errorf("%s in %s: %w", r.Plural, ns, err)
			}
			if m.Metadata.Namespace != "" && m.Metadata.Namespace != ns {
				continue
			}
			it := client.CascadeItem{Kind: kind, Name: m.Metadata.Name, UID: m.Metadata.UID, Deleting: m.Metadata.DeletionTimestamp != nil}
			if kind == "Silo" {
				it.Disks = len(m.Spec.Volumes)
			}
			items = append(items, it)
		}
	}
	Sort(items)
	return items, nil
}

// Progress is where a namespace's emptying is after a Step.
type Progress struct {
	Done    bool                 // nothing is left
	Stage   int                  // the step it is on
	Left    []client.CascadeItem // what that step still waits on
	Refused []string             // deletes the API refused for now (409), "KIND NAME: why"
}

// String is "step 1/5, stop silos: waiting on 2 silos (a, b)", and what was refused.
func (p Progress) String() string {
	if p.Done {
		return "done"
	}
	s := fmt.Sprintf("step %d/%d, %s: waiting on %s", p.Stage+1, len(Stages), Stages[p.Stage].Name, Describe(p.Left))
	if len(p.Refused) > 0 {
		s += "; refused for now: " + strings.Join(p.Refused, "; ")
	}
	return s
}

// StepError is a delete the API refused for good (not a 409 to wait out): the step stops there.
type StepError struct {
	Stage int
	Item  client.CascadeItem
	Err   error
}

func (e *StepError) Error() string {
	one, _ := Noun(e.Item.Kind)
	return fmt.Sprintf("step %d/%d, %s: %s %s: %v", e.Stage+1, len(Stages), Stages[e.Stage].Name, one, e.Item.Name, e.Err)
}

func (e *StepError) Unwrap() error { return e.Err }

// Step deletes, through c, what the first step that still has anything holds in namespace ns,
// and goes on to the next step while one empties at once. It never deletes anything of a later
// step while an earlier one still has something. A 409 is waited out (an IP still held until its
// silo's release is seen, say): the item is in Refused. Any other refusal is a *StepError.
func Step(ctx context.Context, c *client.Client, ns string) (Progress, error) {
	for range len(Stages) + 1 {
		items, err := Contents(ctx, c, ns)
		if err != nil {
			return Progress{}, err
		}
		st, now := Next(items)
		if st < 0 {
			return Progress{Done: true}, nil
		}
		var refused []string
		for _, it := range now {
			if it.Deleting {
				continue
			}
			err := c.Delete(ctx, it.Kind, ns, it.Name, client.Precondition{UID: it.UID})
			var ce *client.Error
			switch {
			case err == nil, client.IsNotFound(err):
			case errors.As(err, &ce) && ce.Code == 409:
				one, _ := Noun(it.Kind)
				refused = append(refused, one+" "+it.Name+": "+ce.Message)
			default:
				return Progress{Stage: st, Left: now}, &StepError{Stage: st, Item: it, Err: err}
			}
		}
		items, err = Contents(ctx, c, ns)
		if err != nil {
			return Progress{}, err
		}
		next, left := Next(items)
		if next != st {
			continue // that step is done: on to the next
		}
		return Progress{Stage: st, Left: left, Refused: refused}, nil
	}
	return Progress{}, errors.New("namespace " + ns + " keeps getting new things while it is being emptied")
}
