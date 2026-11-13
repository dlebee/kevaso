package operators

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// TokenLifetime is how long the token an install gives the controller works; the controller
// renews its own (sdk/operator).
const TokenLifetime = time.Hour

// Host runs a plugin's controller: kvoadm's runs it as a systemd unit over SSH, tests run it in
// the test.
type Host interface {
	// Address is where the controller runs; it's recorded on the Plugin for uninstall.
	Address() string
	// Start installs (or replaces) and starts the controller with its credentials.
	Start(ctx context.Context, c Controller) error
	// Stop stops the controller and removes it and its credentials.
	Stop(ctx context.Context, plugin string) error
}

// Controller is what a host needs to run one.
type Controller struct {
	Plugin  string
	Version string
	Program []byte
	// Credentials, by file name: server, ca.pem, plugin.json, token.json (sdk/operator reads them).
	Credentials map[string][]byte
}

// Installer installs, uninstalls and lists plugin operators through the API, as a cluster-admin.
type Installer struct {
	API *client.Client
	// Server and CA are how the controller reaches the API (its credentials say so).
	Server string
	CA     []byte
	Out    io.Writer
	// Confirm shows the operator what the plugin's controller will be allowed to do and returns
	// whether to go ahead. Nil refuses: nothing is installed without a yes.
	Confirm func(summary string) bool
	// Wait bounds how long a forced uninstall waits for the plugin's controller to finish its
	// objects (finalizers) before it removes what's left (default 30s).
	Wait time.Duration
}

func (in *Installer) say(f string, a ...any) {
	if in.Out != nil {
		_, _ = fmt.Fprintf(in.Out, "→ "+f+"\n", a...)
	}
}

// InstallOptions are the choices kvoadm plugin install offers.
type InstallOptions struct {
	Program []byte // the controller program, built for the host
	Adopt   bool   // take over objects of the same names that no plugin owns
}

// Ref names an object.
func Ref(obj meta.Object) v1.PluginObject {
	m := obj.GetObjectMeta()
	return v1.PluginObject{Kind: obj.GetTypeMeta().Kind, Name: m.Name, Namespace: m.Namespace}
}

func refString(r v1.PluginObject) string {
	if r.Namespace != "" {
		return r.Kind + " " + r.Namespace + "/" + r.Name
	}
	return r.Kind + " " + r.Name
}

// Decision is what an install does with one object.
type Decision string

// Decisions.
const (
	Create Decision = "create"
	Update Decision = "update"
)

// Decide decides, for each object a plugin wants, given what's stored under that name (nil if
// nothing): create it, update it (it's this plugin's, or adopt says take it over), or refuse (it's
// another plugin's, or nobody's without adopt).
func Decide(plugin string, want, stored []meta.Object, adopt bool) ([]Decision, []string) {
	out := make([]Decision, len(want))
	var errs []string
	for i, w := range want {
		s := stored[i]
		if s == nil {
			out[i] = Create
			continue
		}
		switch owner := v1.OwnerPlugin(s.GetObjectMeta()); {
		case owner == plugin:
			out[i] = Update
		case owner != "":
			errs = append(errs, fmt.Sprintf("%s belongs to plugin %s", refString(Ref(w)), owner))
		case adopt:
			out[i] = Update
		default:
			errs = append(errs, fmt.Sprintf("%s already exists and no plugin installed it (--adopt takes it over)", refString(Ref(w))))
		}
	}
	return out, errs
}

// Leftovers are what a plugin owned before and its new version doesn't have.
func Leftovers(before, now []v1.PluginObject) []v1.PluginObject {
	var out []v1.PluginObject
	for _, b := range before {
		if !slices.Contains(now, b) {
			out = append(out, b)
		}
	}
	return out
}

// CheckUninstall decides whether a plugin can go, given how many objects are left of each kind it
// defines: not while any are, unless forced (then they're deleted too).
func CheckUninstall(plugin string, left map[string]int, force bool) error {
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(left)) {
		if n := left[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	if len(parts) == 0 || force {
		return nil
	}
	return fmt.Errorf("plugin %s's kinds still have objects (%s): delete them first, or --force deletes them with the plugin", plugin, strings.Join(parts, ", "))
}

// selfObjects are what every plugin's controller gets to run at all: read its Plugin and write its
// heartbeat, and renew its own token. Bound to its service account with the package's roles.
func selfObjects(plugin string) []meta.Object {
	sa := ServiceAccountName(plugin)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	name := sa + "-self"
	return []meta.Object{
		&v1.ClusterRole{TypeMeta: tm("ClusterRole"), ObjectMeta: meta.ObjectMeta{Name: name}, Rules: []v1.PolicyRule{
			{Verbs: []string{"get"}, Resources: []string{"plugins"}, ResourceNames: []string{plugin}},
			{Verbs: []string{"update"}, Resources: []string{"plugins/status"}, ResourceNames: []string{plugin}},
		}},
		&v1.Role{TypeMeta: tm("Role"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: v1.PluginNamespace}, Rules: []v1.PolicyRule{
			{Verbs: []string{"create"}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{sa}},
		}},
	}
}

// bindings binds each role to the plugin's service account, under the role's name.
func bindings(plugin string, roles []meta.Object) []meta.Object {
	sub := []v1.Subject{{Kind: "ServiceAccount", Name: ServiceAccountName(plugin), Namespace: v1.PluginNamespace}}
	var out []meta.Object
	for _, r := range roles {
		m := r.GetObjectMeta()
		switch r.(type) {
		case *v1.ClusterRole:
			out = append(out, &v1.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"},
				ObjectMeta: meta.ObjectMeta{Name: m.Name}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: m.Name}, Subjects: sub})
		case *v1.Role:
			out = append(out, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
				ObjectMeta: meta.ObjectMeta{Name: m.Name, Namespace: m.Namespace}, RoleRef: v1.RoleRef{Kind: "Role", Name: m.Name}, Subjects: sub})
		}
	}
	return out
}

// wanted is everything an install makes, in order: the service account, the package's objects,
// the controller's own roles, and every binding.
func wanted(p *Package) []meta.Object {
	sa := &v1.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ServiceAccount"},
		ObjectMeta: meta.ObjectMeta{Name: p.ServiceAccount(), Namespace: v1.PluginNamespace}}
	objs := append([]meta.Object{sa}, p.Objects()...)
	self := selfObjects(p.Name())
	objs = append(objs, self...)
	var roles []meta.Object
	for _, r := range p.CRoles {
		roles = append(roles, r)
	}
	for _, r := range p.Roles {
		roles = append(roles, r)
	}
	return append(objs, bindings(p.Name(), append(roles, self...))...)
}

// Summary is what the operator confirms: what the plugin defines, and every power its controller
// gets.
func Summary(p *Package, host string) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	m := p.Manifest
	w("Plugin %s %s: %s", p.Name(), m.Spec.Version, m.Spec.Description)
	var kinds []string
	for _, k := range p.Kinds {
		kinds = append(kinds, k.Spec.Resource())
	}
	w("  defines:  %s", orNone(kinds))
	var pols []string
	for _, x := range p.VPols {
		pols = append(pols, "ValidationPolicy "+x.Name)
	}
	for _, x := range p.MPols {
		pols = append(pols, "MutationPolicy "+x.Name)
	}
	w("  policies: %s", orNone(pols))
	w("Its controller runs on %s as %s/%s, allowed to:", host, v1.PluginNamespace, p.ServiceAccount())
	rules := func(where string, rs []v1.PolicyRule) {
		for _, r := range rs {
			names := ""
			if len(r.ResourceNames) > 0 {
				names = " (only " + strings.Join(r.ResourceNames, ", ") + ")"
			}
			w("  %-28s %s%s, %s", strings.Join(r.Verbs, " "), strings.Join(r.Resources, " "), names, where)
		}
	}
	for _, r := range p.CRoles {
		rules("in every namespace", r.Rules)
	}
	for _, r := range p.Roles {
		rules("in "+r.Namespace, r.Rules)
	}
	w("and, to run at all (every plugin gets these):")
	for _, o := range selfObjects(p.Name()) {
		switch r := o.(type) {
		case *v1.ClusterRole:
			rules("its heartbeat", r.Rules)
		case *v1.Role:
			rules("renewing its own token", r.Rules)
		}
	}
	return b.String()
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}

func newOf(kind string) (meta.Object, error) {
	k, ok := v1.Lookup(kind)
	if !ok {
		return nil, fmt.Errorf("unknown kind %s", kind)
	}
	return k.New(), nil
}

// stored reads an object by its reference (nil, nil if it doesn't exist).
func (in *Installer) stored(ctx context.Context, r v1.PluginObject) (meta.Object, error) {
	obj, err := newOf(r.Kind)
	if err != nil {
		return nil, err
	}
	if err := in.API.Get(ctx, r.Kind, r.Namespace, r.Name, obj); client.IsNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return obj, nil
}

func ownedBy(p *v1.Plugin) meta.OwnerReference {
	return meta.OwnerReference{APIVersion: v1.APIVersion, Kind: "Plugin", Name: p.Name, UID: p.UID}
}

func setOwner(m *meta.ObjectMeta, ref meta.OwnerReference) {
	m.OwnerReferences = slices.DeleteFunc(m.OwnerReferences, func(r meta.OwnerReference) bool { return r.APIVersion == v1.APIVersion && r.Kind == "Plugin" })
	m.OwnerReferences = append(m.OwnerReferences, ref)
}

// Install installs or upgrades a plugin: it checks who owns what the package names, asks the
// operator, applies everything owned by the Plugin, gives the controller a token and starts it.
func (in *Installer) Install(ctx context.Context, p *Package, host Host, o InstallOptions) error {
	want := wanted(p)
	stored := make([]meta.Object, len(want))
	for i, w := range want {
		s, err := in.stored(ctx, Ref(w))
		if err != nil {
			return err
		}
		stored[i] = s
	}
	decisions, errs := Decide(p.Name(), want, stored, o.Adopt)
	var prev v1.Plugin
	err := in.API.Get(ctx, "Plugin", "", p.Name(), &prev)
	switch {
	case client.IsNotFound(err):
	case err != nil:
		return err
	case prev.DeletionTimestamp != nil:
		errs = append(errs, fmt.Sprintf("plugin %s is being uninstalled: finish with kvoadm plugin uninstall %s", p.Name(), p.Name()))
	}
	if len(errs) > 0 {
		return fmt.Errorf("can't install plugin %s:\n  %s", p.Name(), strings.Join(errs, "\n  "))
	}
	if in.Confirm == nil || !in.Confirm(Summary(p, host.Address())) {
		return errors.New("not installed")
	}

	if err := in.API.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"},
		ObjectMeta: meta.ObjectMeta{Name: v1.PluginNamespace}}); err != nil && !client.IsAlreadyExists(err) {
		return err
	}
	owns := make([]v1.PluginObject, len(want))
	for i, w := range want {
		owns[i] = Ref(w)
	}
	plugin := prev
	plugin.TypeMeta = meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Plugin"}
	plugin.Name = p.Name()
	if !slices.Contains(plugin.Finalizers, v1.PluginFinalizer) {
		plugin.Finalizers = append(plugin.Finalizers, v1.PluginFinalizer)
	}
	before := prev.Spec.Owns
	plugin.Spec = v1.PluginSpec{Version: p.Manifest.Spec.Version, Description: p.Manifest.Spec.Description, Owns: owns,
		Controller: &v1.PluginController{Host: host.Address(), ServiceAccount: p.ServiceAccount()}}
	if plugin.UID == "" {
		err = in.API.Create(ctx, &plugin)
	} else {
		err = in.API.Update(ctx, &plugin)
	}
	if err != nil {
		return fmt.Errorf("plugin %s: %w", p.Name(), err)
	}
	owner := ownedBy(&plugin)
	for i, w := range want {
		setOwner(w.GetObjectMeta(), owner)
		switch decisions[i] {
		case Create:
			err = in.API.Create(ctx, w)
		case Update:
			w.GetObjectMeta().ResourceVersion = stored[i].GetObjectMeta().ResourceVersion
			w.GetObjectMeta().Finalizers = stored[i].GetObjectMeta().Finalizers
			err = in.API.Update(ctx, w)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", refString(Ref(w)), err)
		}
		in.say("%s %sd", refString(Ref(w)), decisions[i])
	}
	if err := in.removeOwned(ctx, p.Name(), Leftovers(before, owns)); err != nil {
		return fmt.Errorf("what the new version no longer has: %w", err)
	}
	creds, err := in.credentials(ctx, p)
	if err != nil {
		return err
	}
	if err := host.Start(ctx, Controller{Plugin: p.Name(), Version: p.Manifest.Spec.Version, Program: o.Program, Credentials: creds}); err != nil {
		return fmt.Errorf("starting plugin %s's controller on %s: %w", p.Name(), host.Address(), err)
	}
	in.say("plugin %s %s installed; its controller runs on %s as %s/%s", p.Name(), p.Manifest.Spec.Version, host.Address(), v1.PluginNamespace, p.ServiceAccount())
	return nil
}

// credentials are the controller's files: where the API is, the CA, who it is, and a fresh token.
func (in *Installer) credentials(ctx context.Context, p *Package) (map[string][]byte, error) {
	path, err := client.Path("ServiceAccount", v1.PluginNamespace, p.ServiceAccount())
	if err != nil {
		return nil, err
	}
	var tok client.TokenResponse
	if err := in.API.Call(ctx, http.MethodPost, path+"/token", client.TokenRequest{Duration: TokenLifetime.String()}, &tok); err != nil {
		return nil, fmt.Errorf("a token for %s: %w", p.ServiceAccount(), err)
	}
	id, _ := json.Marshal(map[string]string{"name": p.Name(), "version": p.Manifest.Spec.Version,
		"serviceAccount": v1.PluginNamespace + "/" + p.ServiceAccount()})
	tj, _ := json.Marshal(tok)
	return map[string][]byte{"server": []byte(in.Server + "\n"), "ca.pem": in.CA, "plugin.json": id, "token.json": tj}, nil
}

// removeOwned deletes objects a plugin owns, last first. A definition still holding objects is
// refused by the API server: that's for the caller to have checked.
func (in *Installer) removeOwned(ctx context.Context, plugin string, refs []v1.PluginObject) error {
	for i := len(refs) - 1; i >= 0; i-- {
		r := refs[i]
		s, err := in.stored(ctx, r)
		if err != nil {
			return err
		}
		if s == nil || v1.OwnerPlugin(s.GetObjectMeta()) != plugin {
			continue // gone, or someone else's now: not ours to delete
		}
		if err := in.API.Delete(ctx, r.Kind, r.Namespace, r.Name); err != nil && !client.IsNotFound(err) {
			return fmt.Errorf("%s: %w", refString(r), err)
		}
		in.say("%s deleted", refString(r))
	}
	return nil
}

// Uninstall removes a plugin: refused while its kinds have objects unless forced. It marks the
// Plugin as going (so its definitions may be deleted), deletes its objects if forced, stops its
// controller, removes everything it owns, and then the Plugin. Running it again finishes an
// uninstall that stopped half-way.
func (in *Installer) Uninstall(ctx context.Context, name string, hostFor func(address string) (Host, error), force bool) error {
	var p v1.Plugin
	if err := in.API.Get(ctx, "Plugin", "", name, &p); err != nil {
		return fmt.Errorf("plugin %s: %w", name, err)
	}
	left := map[string]int{}
	for _, k := range p.Kinds() {
		n, err := in.count(ctx, k)
		if err != nil {
			return err
		}
		left[k] = n
	}
	if err := CheckUninstall(name, left, force); err != nil {
		return err
	}
	if p.DeletionTimestamp == nil {
		if err := in.API.Delete(ctx, "Plugin", "", name); err != nil {
			return err
		}
	}
	if force {
		if err := in.deleteObjects(ctx, p.Kinds()); err != nil {
			return err
		}
	}
	if c := p.Spec.Controller; c != nil && c.Host != "" {
		h, err := hostFor(c.Host)
		if err != nil {
			return err
		}
		if err := h.Stop(ctx, name); err != nil {
			return fmt.Errorf("stopping plugin %s's controller on %s: %w", name, c.Host, err)
		}
		in.say("plugin %s's controller stopped on %s", name, c.Host)
	}
	if err := in.removeOwned(ctx, name, p.Spec.Owns); err != nil {
		return err
	}
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Plugin
		if err := in.API.Get(ctx, "Plugin", "", name, &cur); client.IsNotFound(err) {
			break
		} else if err != nil {
			return err
		}
		cur.Finalizers = slices.DeleteFunc(cur.Finalizers, func(f string) bool { return f == v1.PluginFinalizer })
		if err := in.API.Update(ctx, &cur); err == nil || client.IsNotFound(err) {
			break
		} else if !client.IsConflict(err) {
			return err
		}
	}
	in.say("plugin %s uninstalled", name)
	return nil
}

func (in *Installer) count(ctx context.Context, resource string) (int, error) {
	l, err := in.API.List(ctx, resource, "")
	if client.IsNotFound(err) {
		return 0, nil // the definition is gone already
	}
	if err != nil {
		return 0, err
	}
	return len(l.Items), nil
}

// deleteObjects deletes every object of the kinds, waits for their finalizers (the controller is
// still running), and then removes the finalizers of what's left.
func (in *Installer) deleteObjects(ctx context.Context, kinds []string) error {
	each := func(f func(resource string, u *v1.Unstructured) error) error {
		for _, k := range kinds {
			l, err := in.API.List(ctx, k, "")
			if client.IsNotFound(err) {
				continue
			} else if err != nil {
				return err
			}
			for _, item := range l.Items {
				obj, _, err := v1.Decode(item)
				if err != nil {
					return err
				}
				if err := f(k, obj.(*v1.Unstructured)); err != nil && !client.IsNotFound(err) {
					return err
				}
			}
		}
		return nil
	}
	if err := each(func(resource string, u *v1.Unstructured) error {
		in.say("deleting %s %s/%s", resource, u.Namespace, u.Name)
		return in.API.Delete(ctx, resource, u.Namespace, u.Name)
	}); err != nil {
		return err
	}
	wait := in.Wait
	if wait <= 0 {
		wait = 30 * time.Second
	}
	for end := time.Now().Add(wait); time.Now().Before(end); {
		total := 0
		for _, k := range kinds {
			n, err := in.count(ctx, k)
			if err != nil {
				return err
			}
			total += n
		}
		if total == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return each(func(resource string, u *v1.Unstructured) error {
		in.say("%s %s/%s: its controller didn't finish it; removing its finalizers", resource, u.Namespace, u.Name)
		u.Finalizers = nil
		return in.API.Update(ctx, u)
	})
}

// Listed is one plugin as kvoadm plugin list shows it.
type Listed struct {
	Name, Version, Host string
	Kinds               []string
	Running             bool
	Heartbeat           *time.Time
	Uninstalling        bool
}

// List lists the installed plugins.
func (in *Installer) List(ctx context.Context, now time.Time) ([]Listed, error) {
	l, err := in.API.List(ctx, "Plugin", "")
	if err != nil {
		return nil, err
	}
	var out []Listed
	for _, item := range l.Items {
		obj, _, err := v1.Decode(item)
		if err != nil {
			return nil, err
		}
		p := obj.(*v1.Plugin)
		x := Listed{Name: p.Name, Version: p.Spec.Version, Kinds: p.Kinds(), Running: p.Running(now),
			Heartbeat: p.Status.Controller.Heartbeat, Uninstalling: p.DeletionTimestamp != nil}
		if p.Spec.Controller != nil {
			x.Host = p.Spec.Controller.Host
		}
		out = append(out, x)
	}
	slices.SortFunc(out, func(a, b Listed) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
