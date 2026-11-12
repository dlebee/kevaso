// Package kvo is the user CLI. Run takes its arguments and streams, so tests drive it directly.
//
//	kvo apply -f FILE|-             create or update every object in a YAML/JSON file
//	kvo get KIND [NAME] [-n NS|-A] [-o yaml|json]
//	kvo delete KIND NAME [-n NS]
//	kvo watch KIND [-n NS|-A]
//
// The server comes from --server or $KVO_SERVER (default http://127.0.0.1:8080, `kevasod dev`).
// M2 adds TLS and contexts, M4 `kvo login`.
package kvo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// DefaultServer is where `kevasod dev` listens.
const DefaultServer = "http://127.0.0.1:8080"

type opts struct {
	server, namespace, output, file string
	all                             bool
	args                            []string
}

func parse(args []string, env func(string) string) (opts, error) {
	o := opts{server: env("KVO_SERVER"), namespace: ""}
	if o.server == "" {
		o.server = DefaultServer
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func() (string, error) {
			if k, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(k, "-") {
				return v, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		name, _, _ := strings.Cut(a, "=")
		var err error
		switch name {
		case "--server":
			o.server, err = val()
		case "-n", "--namespace":
			o.namespace, err = val()
		case "-o", "--output":
			o.output, err = val()
		case "-f", "--filename":
			o.file, err = val()
		case "-A", "--all-namespaces":
			o.all = true
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				return o, fmt.Errorf("unknown flag %s", a)
			}
			o.args = append(o.args, a)
		}
		if err != nil {
			return o, err
		}
	}
	return o, nil
}

// Run runs one kvo command and returns its exit code.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: kvo apply|get|delete|watch …")
		return 2
	}
	o, err := parse(args[1:], os.Getenv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "kvo:", err)
		return 2
	}
	c := client.New(o.server)
	switch args[0] {
	case "apply":
		err = apply(ctx, c, o, stdin, stdout)
	case "get":
		err = get(ctx, c, o, stdout)
	case "delete":
		err = del(ctx, c, o, stdout)
	case "watch":
		err = watch(ctx, c, o, stdout)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "kvo:", err)
		return 1
	}
	return 0
}

func defaultNS(o opts) string {
	if o.namespace != "" {
		return o.namespace
	}
	return "default"
}

func kindOf(name string) (v1.KindInfo, error) {
	k, ok := v1.Lookup(name)
	if !ok {
		k, ok = v1.Lookup(strings.TrimSuffix(name, "s"))
	}
	if !ok {
		for _, kk := range v1.Kinds() {
			if strings.EqualFold(kk.Kind, name) || strings.EqualFold(kk.Plural, name) {
				return kk, nil
			}
		}
		return v1.KindInfo{}, fmt.Errorf("unknown kind %q (known: %s)", name, knownKinds())
	}
	return k, nil
}

func knownKinds() string {
	var ks []string
	for _, k := range v1.Kinds() {
		ks = append(ks, k.Plural)
	}
	return strings.Join(ks, ", ")
}

// ── apply ────────────────────────────────────────────────────────────────────

// readDocs splits YAML (one or many documents, or JSON) into JSON objects.
func readDocs(r io.Reader) ([][]byte, error) {
	dec := yaml.NewDecoder(r)
	var out [][]byte
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if doc == nil {
			continue
		}
		b, err := json.Marshal(doc)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
}

func apply(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout io.Writer) error {
	if o.file == "" {
		return errors.New("apply needs -f FILE (or -f - for stdin)")
	}
	r := stdin
	if o.file != "-" {
		f, err := os.Open(o.file)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	docs, err := readDocs(r)
	if err != nil {
		return fmt.Errorf("%s: %w", o.file, err)
	}
	for _, doc := range docs {
		obj, k, err := v1.Decode(doc)
		if err != nil {
			return err
		}
		m := obj.GetObjectMeta()
		if k.Scope == v1.Namespaced && m.Namespace == "" {
			m.Namespace = defaultNS(o)
		}
		what := strings.ToLower(k.Kind) + "/" + m.Name
		cur := k.New()
		err = c.Get(ctx, k.Kind, m.Namespace, m.Name, cur)
		switch {
		case client.IsNotFound(err):
			if err := c.Create(ctx, obj); err != nil {
				return fmt.Errorf("%s: %w", what, err)
			}
			_, _ = fmt.Fprintln(stdout, what, "created")
		case err != nil:
			return fmt.Errorf("%s: %w", what, err)
		default:
			same, err := sameDeclared(obj, cur)
			if err != nil {
				return err
			}
			if same {
				_, _ = fmt.Fprintln(stdout, what, "unchanged")
				continue
			}
			m.ResourceVersion = cur.GetObjectMeta().ResourceVersion
			if err := c.Update(ctx, obj); err != nil {
				return fmt.Errorf("%s: %w", what, err)
			}
			_, _ = fmt.Fprintln(stdout, what, "configured")
		}
	}
	return nil
}

// sameDeclared reports whether the stored object already matches what's declared: the spec and the
// user-owned metadata (labels, annotations, finalizers, owners). Status and system fields are ignored.
func sameDeclared(declared, stored meta.Object) (bool, error) {
	a, err := declaredPart(declared)
	if err != nil {
		return false, err
	}
	b, err := declaredPart(stored)
	if err != nil {
		return false, err
	}
	return a == b, nil
}

func declaredPart(obj meta.Object) (string, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return "", err
	}
	md, _ := m["metadata"].(map[string]any)
	keep := map[string]any{}
	for _, f := range []string{"labels", "annotations", "finalizers", "ownerReferences"} {
		if v, ok := md[f]; ok {
			keep[f] = v
		}
	}
	out, err := json.Marshal(map[string]any{"spec": m["spec"], "metadata": keep})
	return string(out), err
}

// ── get ──────────────────────────────────────────────────────────────────────

func get(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) < 1 {
		return fmt.Errorf("get needs a kind (%s)", knownKinds())
	}
	k, err := kindOf(o.args[0])
	if err != nil {
		return err
	}
	ns := ""
	if k.Scope == v1.Namespaced && !o.all {
		ns = defaultNS(o)
	}
	var objs []meta.Object
	if len(o.args) >= 2 {
		obj := k.New()
		if err := c.Get(ctx, k.Kind, ns, o.args[1], obj); err != nil {
			return err
		}
		objs = append(objs, obj)
	} else {
		l, err := c.List(ctx, k.Kind, ns)
		if err != nil {
			return err
		}
		for _, item := range l.Items {
			obj, _, err := v1.Decode(item)
			if err != nil {
				return err
			}
			objs = append(objs, obj)
		}
	}
	switch o.output {
	case "json":
		return printJSON(stdout, objs)
	case "yaml":
		return printYAML(stdout, objs)
	case "", "wide":
		return printTable(stdout, k, objs, o.all)
	default:
		return fmt.Errorf("unknown output %q: use yaml, json or wide", o.output)
	}
}

func printJSON(w io.Writer, objs []meta.Object) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if len(objs) == 1 {
		return enc.Encode(objs[0])
	}
	return enc.Encode(objs)
}

func printYAML(w io.Writer, objs []meta.Object) error {
	for i, obj := range objs {
		b, err := json.Marshal(obj)
		if err != nil {
			return err
		}
		var m any
		if err := yaml.Unmarshal(b, &m); err != nil {
			return err
		}
		if i > 0 {
			_, _ = fmt.Fprintln(w, "---")
		}
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(m); err != nil {
			return err
		}
		_, _ = w.Write(buf.Bytes())
	}
	return nil
}

func age(m *meta.ObjectMeta) string {
	if m.CreationTimestamp == nil {
		return "-"
	}
	d := time.Since(*m.CreationTimestamp).Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func printTable(w io.Writer, k v1.KindInfo, objs []meta.Object, all bool) error {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	var head []string
	if all && k.Scope == v1.Namespaced {
		head = append(head, "NAMESPACE")
	}
	head = append(head, "NAME")
	switch k.Kind {
	case "Silo":
		head = append(head, "RUNTIME", "PHASE", "HOST")
	case "Host":
		head = append(head, "ADDRESS", "COMPONENTS", "RUNTIMES")
	case "Namespace":
		head = append(head, "STATUS")
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
		switch o := obj.(type) {
		case *v1.Silo:
			row = append(row, o.Spec.Runtime, dash(o.Status.Phase), dash(o.Status.Host))
		case *v1.Host:
			var comps, rts []string
			if o.Spec.Components.ControlPlane != nil {
				comps = append(comps, "control-plane")
			}
			if w := o.Spec.Components.Worker; w != nil {
				comps = append(comps, "worker")
				for _, r := range w.Runtimes {
					rts = append(rts, r.Name)
				}
			}
			row = append(row, o.Spec.Address, strings.Join(comps, ","), dash(strings.Join(rts, ",")))
		case *v1.Namespace:
			row = append(row, dash(o.Status.Phase))
		}
		row = append(row, age(m))
		_, _ = fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

// ── delete, watch ────────────────────────────────────────────────────────────

func del(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("delete needs KIND NAME")
	}
	k, err := kindOf(o.args[0])
	if err != nil {
		return err
	}
	ns := ""
	if k.Scope == v1.Namespaced {
		ns = defaultNS(o)
	}
	if err := c.Delete(ctx, k.Kind, ns, o.args[1]); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "%s/%s deleted\n", strings.ToLower(k.Kind), o.args[1])
	return nil
}

func watch(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 1 {
		return errors.New("watch needs KIND")
	}
	k, err := kindOf(o.args[0])
	if err != nil {
		return err
	}
	ns := ""
	if k.Scope == v1.Namespaced && !o.all {
		ns = defaultNS(o)
	}
	l, err := c.List(ctx, k.Kind, ns)
	if err != nil {
		return err
	}
	ch, err := c.Watch(ctx, k.Kind, ns, l.Metadata.ResourceVersion)
	if err != nil {
		return err
	}
	for ev := range ch {
		obj, _, err := v1.Decode(ev.Object)
		if err != nil {
			return err
		}
		m := obj.GetObjectMeta()
		name := m.Name
		if m.Namespace != "" {
			name = m.Namespace + "/" + m.Name
		}
		_, _ = fmt.Fprintf(stdout, "%-8s %s/%s @%s\n", ev.Type, strings.ToLower(k.Kind), name, m.ResourceVersion)
	}
	if ctx.Err() != nil {
		return nil // stopped on purpose
	}
	return errors.New("watch ended by the server")
}
