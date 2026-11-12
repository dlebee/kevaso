// Package kvo is the user CLI. Run takes its arguments and streams, so tests drive it directly.
//
//	kvo apply -f FILE|-             create or update every object in a YAML/JSON file
//	kvo get KIND [NAME] [-n NS|-A] [-o yaml|json]
//	kvo describe KIND NAME [-n NS]   everything about one object, for people
//	kvo delete KIND NAME [-n NS]
//	kvo watch KIND [-n NS|-A]
//	kvo exec silo NAME [-n NS] -- CMD [ARGS…]   run a command in a silo; exits with its code
//	kvo login [SERVER --ca sha256:…] [--context NAME] [--no-browser]   sign in (browser + invite code)
//	kvo logout                    forget this context's session
//	kvo ctx [NAME]                list contexts, or switch to one
//	kvo ns [NAME]                 show the default namespace, or set it for this context
//	kvo auth can-i VERB RESOURCE[/NAME|/SUBRESOURCE] [-n NS]   exits 0 for yes, 1 for no
//	kvo auth whoami
//	kvo create token NAME [-n NS] [--duration 1h]   a service account token, for CI ($KVO_TOKEN)
//	kvo create secret NAME (--from-file F|- | --generate) [--type opaque|ed25519|ecdsa-p256]
//	        [--write-only] [--allow broker,inject,file,env] [-l KEY=VALUE]…   values never on argv
//	kvo secret set NAME --from-file F|-        rotate: every silo using it follows
//	kvo get secret NAME --reveal               the value (read-value; never a write-only secret)
//
// The cluster comes from --server or $KVO_SERVER (plain HTTP, for `kevasod dev`), otherwise from the
// kvo config's current context (or --context): TLS with a pinned CA and a client certificate, as
// `kvoadm init` writes it. With neither, it's http://127.0.0.1:8080. M4 adds `kvo login`.
package kvo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/kvoconfig"
)

// DefaultServer is where `kevasod dev` listens.
const DefaultServer = "http://127.0.0.1:8080"

type opts struct {
	server, context, namespace, output, file string
	ca                                       string // kvo login: the CA fingerprint to pin
	duration                                 string // kvo create token
	all, noBrowser                           bool
	secret                                   secretOpts
	args                                     []string
	command                                  []string // after --
	ctxNamespace                             string   // the context's default namespace
}

func parse(args []string, env func(string) string) (opts, error) {
	o := opts{server: env("KVO_SERVER")}
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
		if a == "--" {
			o.command = args[i+1:]
			break
		}
		name, _, _ := strings.Cut(a, "=")
		var err error
		switch name {
		case "--server":
			o.server, err = val()
		case "--context":
			o.context, err = val()
		case "-n", "--namespace":
			o.namespace, err = val()
		case "-o", "--output":
			o.output, err = val()
		case "-f", "--filename":
			o.file, err = val()
		case "-A", "--all-namespaces":
			o.all = true
		case "--ca":
			o.ca, err = val()
		case "--no-browser":
			o.noBrowser = true
		case "--duration":
			o.duration, err = val()
		case "--from-file":
			o.secret.fromFile, err = val()
		case "--from-literal":
			o.secret.fromLiteral, err = val()
			o.secret.literalSet = true
		case "--i-know":
			o.secret.iKnow = true
		case "--generate":
			o.secret.generate = true
		case "--type":
			o.secret.typ, err = val()
		case "--write-only":
			o.secret.writeOnly = true
		case "--allow":
			var v string
			v, err = val()
			o.secret.allow = append(o.secret.allow, strings.Split(v, ",")...)
		case "-l", "--label":
			var v string
			v, err = val()
			o.secret.labels = append(o.secret.labels, v)
		case "--reveal":
			o.secret.reveal = true
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
		_, _ = fmt.Fprintln(stderr, "usage: kvo apply|get|describe|delete|watch|exec|create|secret|login|logout|ctx|ns|auth …")
		return 2
	}
	o, err := parse(args[1:], os.Getenv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "kvo:", err)
		return 2
	}
	switch args[0] { // commands about the config itself
	case "login", "logout", "ctx", "ns":
		if err := configCommand(ctx, args[0], o, stdout, stderr); err != nil {
			_, _ = fmt.Fprintln(stderr, "kvo:", err)
			return 1
		}
		return 0
	}
	c, err := clientFor(&o)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "kvo:", err)
		return 1
	}
	switch args[0] {
	case "auth":
		var code int
		code, err = auth(ctx, c, o, stdout)
		if err == nil {
			return code
		}
	case "apply":
		err = apply(ctx, c, o, stdin, stdout)
	case "get":
		err = get(ctx, c, o, stdout)
	case "describe":
		err = describe(ctx, c, o, stdout)
	case "create":
		if len(o.args) > 0 && o.args[0] == "secret" {
			err = createSecret(ctx, c, o, stdin, stdout)
		} else {
			err = createToken(ctx, c, o, stdout)
		}
	case "secret":
		err = secretCommand(ctx, c, o, stdin, stdout)
	case "delete":
		err = del(ctx, c, o, stdout)
	case "watch":
		err = watch(ctx, c, o, stdout)
	case "exec":
		var code int
		code, err = execIn(ctx, c, o, stdin, stdout, stderr)
		if err == nil {
			return code
		}
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "kvo:", err)
		return 1
	}
	return 0
}

// clientFor picks the cluster: --server / $KVO_SERVER, else the kvo config, else kevasod dev.
//
// For CI and scripts, $KVO_TOKEN (a service account token, from kvo create token) is sent as the
// bearer token: with --server https://… it needs $KVO_CA_FILE (the cluster CA); with a context it
// uses that context's server and CA and nothing else from it.
func clientFor(o *opts) (*client.Client, error) {
	token := os.Getenv("KVO_TOKEN")
	if o.server != "" {
		if token == "" || !strings.HasPrefix(o.server, "https://") {
			return client.New(o.server), nil
		}
		ca, err := os.ReadFile(os.Getenv("KVO_CA_FILE"))
		if err != nil {
			return nil, fmt.Errorf("KVO_TOKEN with an https server needs KVO_CA_FILE: %w", err)
		}
		c, err := client.NewTLS(o.server, ca, nil, nil)
		if err != nil {
			return nil, err
		}
		c.Token = func(context.Context) (string, error) { return token, nil }
		return c, nil
	}
	path, err := kvoconfig.Path()
	if err != nil {
		return nil, err
	}
	cfg, err := kvoconfig.Load(path)
	if err != nil {
		return nil, err
	}
	if len(cfg.Contexts) == 0 && o.context == "" {
		return client.New(DefaultServer), nil
	}
	if token != "" {
		name, kc, err := cfg.Resolve(o.context)
		if err != nil {
			return nil, err
		}
		ca, err := os.ReadFile(kc.CA)
		if err != nil {
			return nil, err
		}
		c, err := client.NewTLS(kc.Server, ca, nil, nil)
		if err != nil {
			return nil, err
		}
		c.Token = func(context.Context) (string, error) { return token, nil }
		o.ctxNamespace = cfg.Contexts[name].Namespace
		return c, nil
	}
	c, name, err := cfg.Client(path, o.context)
	if err == nil {
		o.ctxNamespace = cfg.Contexts[name].Namespace
	}
	return c, err
}

// createToken: kvo create token NAME [-n NS] [--duration 1h] prints a service account token.
func createToken(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 || o.args[0] != "token" {
		return errors.New("create token needs the service account's NAME (kvo create token NAME -n NS)")
	}
	p, err := client.Path("ServiceAccount", defaultNS(o), o.args[1])
	if err != nil {
		return err
	}
	var resp client.TokenResponse
	if err := c.Call(ctx, http.MethodPost, p+"/token", client.TokenRequest{Duration: o.duration}, &resp); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, resp.Token)
	return nil
}

func defaultNS(o opts) string {
	switch {
	case o.namespace != "":
		return o.namespace
	case o.ctxNamespace != "":
		return o.ctxNamespace
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
			if strings.EqualFold(kk.Kind, name) || strings.EqualFold(kk.Plural, name) || slices.Contains(kk.ShortNames, strings.ToLower(name)) {
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
	if o.secret.reveal {
		if k.Kind != "Secret" || len(o.args) != 2 {
			return errors.New("--reveal works with one secret: kvo get secret NAME --reveal")
		}
		return revealSecret(ctx, c, ns, o.args[1], stdout)
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
	return since(*m.CreationTimestamp)
}

// since is a short duration from t to now: 42s, 5m, 3h, 2d.
func since(t time.Time) string {
	d := time.Since(t).Round(time.Second)
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

// summary is one line of an object's state, for watch.
func summary(obj meta.Object) string {
	var parts []string
	var conds []meta.Condition
	switch o := obj.(type) {
	case *v1.Silo:
		parts = append(parts, "phase="+dash(o.Status.Phase), "host="+dash(o.Status.Host))
		n := len(o.Status.Init)
		if o.Spec.Init != nil {
			n = max(n, len(o.Spec.Init.Steps))
		}
		if n > 0 {
			done := 0
			for _, st := range o.Status.Init {
				if st.State == "Done" {
					done++
				}
			}
			parts = append(parts, fmt.Sprintf("init=%d/%d", done, n))
		}
		if o.Status.Address != "" {
			parts = append(parts, "address="+o.Status.Address)
		}
		conds = o.Status.Conditions
	case *v1.Host:
		names := make([]string, 0, len(o.Status.Runtimes))
		for n := range o.Status.Runtimes {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			rs := o.Status.Runtimes[n]
			p := n + "=" + rs.State
			if rs.Message != "" && rs.State != "Ready" {
				p += " (" + rs.Message + ")"
			}
			parts = append(parts, p)
		}
		conds = o.Status.Conditions
	}
	for _, cd := range conds { // say why something isn't true yet
		if cd.Status != meta.ConditionTrue && cd.Message != "" {
			parts = append(parts, fmt.Sprintf("%s: %s", cd.Type, cd.Message))
		}
	}
	return strings.Join(parts, "  ")
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
		head = append(head, "ADDRESS", "REGION", "COMPONENTS", "RUNTIMES")
	case "Namespace":
		head = append(head, "STATUS")
	case "Secret":
		head = append(head, "TYPE", "VERSION", "UPDATED", "READABLE")
	case "Grant":
		head = append(head, "EGRESS", "SECRETS")
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
					if st, ok := o.Status.Runtimes[r.Name]; ok {
						rts = append(rts, r.Name+":"+st.State)
					} else {
						rts = append(rts, r.Name)
					}
				}
			}
			region := dash(o.Spec.Region)
			if o.Spec.Zone != "" {
				region += "/" + o.Spec.Zone
			}
			if o.Spec.Unschedulable {
				comps = append(comps, "cordoned")
			}
			row = append(row, o.Spec.Address, region, strings.Join(comps, ","), dash(strings.Join(rts, ",")))
		case *v1.Namespace:
			row = append(row, dash(o.Status.Phase))
		case *v1.Secret:
			typ, updated, readable := o.Spec.Type, "-", "yes"
			if typ == "" {
				typ = v1.SecretOpaque
			}
			if o.Status.UpdatedAt != nil {
				updated = since(*o.Status.UpdatedAt)
			}
			if !o.Readable() {
				readable = "write-only"
			}
			ver := "no value"
			if o.Status.Version > 0 {
				ver = fmt.Sprint(o.Status.Version)
			}
			row = append(row, typ, ver, updated, readable)
		case *v1.Grant:
			var eg, secs []string
			for _, e := range o.Spec.Egress {
				eg = append(eg, e.To)
			}
			for _, sc := range o.Spec.Secrets {
				secs = append(secs, sc.Name+":"+sc.Delivery())
			}
			if op := o.Spec.Operations; op != nil && op.Sign != nil {
				secs = append(secs, op.Sign.KeyRef+":sign")
			}
			row = append(row, dash(strings.Join(eg, ",")), dash(strings.Join(secs, ",")))
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

// execIn runs o.command in a silo, wiring this process's streams to it.
func execIn(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(o.args) != 2 || len(o.command) == 0 {
		return 0, errors.New("exec needs silo NAME -- COMMAND")
	}
	if k, err := kindOf(o.args[0]); err != nil || k.Kind != "Silo" {
		return 0, errors.New("exec works on silos: kvo exec silo NAME -- COMMAND")
	}
	return c.Exec(ctx, defaultNS(o), o.args[1], o.command, stdin, stdout, stderr)
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
	line := func(typ string, raw json.RawMessage) error {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return err
		}
		m := obj.GetObjectMeta()
		name := m.Name
		if m.Namespace != "" {
			name = m.Namespace + "/" + m.Name
		}
		_, _ = fmt.Fprintf(stdout, "%s %-8s %s/%s  %s\n", time.Now().Format("15:04:05"), typ, strings.ToLower(k.Kind), name, summary(obj))
		return nil
	}
	for _, it := range l.Items { // what's there now, then every change
		if err := line("NOW", it); err != nil {
			return err
		}
	}
	for ev := range ch {
		if err := line(string(ev.Type), ev.Object); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return nil // stopped on purpose
	}
	return errors.New("watch ended by the server")
}
