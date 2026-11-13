// Package operators installs plugin operators (design §4.2, §6; ADR 0006): a package of files a
// person can read — plugin.yaml, its KindDefinitions, admission policies and the roles its
// controller needs — and the controller's program. kvoadm plugin install, uninstall and list are
// thin around it, and the integration test drives the same code with the host faked.
package operators

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Manifest is plugin.yaml.
type Manifest struct {
	APIVersion string       `json:"apiVersion"` // kevaso/v1
	Kind       string       `json:"kind"`       // PluginPackage
	Metadata   ManifestMeta `json:"metadata"`
	Spec       ManifestSpec `json:"spec"`
}

// ManifestMeta names the plugin.
type ManifestMeta struct {
	Name string `json:"name"`
}

// ManifestSpec is the package.
type ManifestSpec struct {
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	// Controller is the plugin's controller program, a file in the package built for the host
	// (kvoadm plugin install --binary can point elsewhere).
	Controller ManifestController `json:"controller"`
	// Resources are YAML files in the package, each one or more documents: KindDefinitions,
	// ValidationPolicies and MutationPolicies (on the package's own kinds only), and the
	// ClusterRoles and Roles the controller is given.
	Resources []string `json:"resources"`
}

// ManifestController is the controller program.
type ManifestController struct {
	Binary string `json:"binary"`
}

// Package is a loaded plugin package.
type Package struct {
	Manifest Manifest
	Dir      string
	Kinds    []*v1.KindDefinition
	VPols    []*v1.ValidationPolicy
	MPols    []*v1.MutationPolicy
	CRoles   []*v1.ClusterRole
	Roles    []*v1.Role
}

// Name is the plugin's name.
func (p *Package) Name() string { return p.Manifest.Metadata.Name }

// ServiceAccount is the name of the controller's service account (in v1.PluginNamespace).
func (p *Package) ServiceAccount() string { return ServiceAccountName(p.Name()) }

// ServiceAccountName is a plugin's controller's service account.
func ServiceAccountName(plugin string) string { return "plugin-" + plugin }

// Objects are the package's objects, in the order they're applied: kinds, then the policies on
// them, then roles.
func (p *Package) Objects() []meta.Object {
	var out []meta.Object
	for _, k := range p.Kinds {
		out = append(out, k)
	}
	for _, x := range p.VPols {
		out = append(out, x)
	}
	for _, x := range p.MPols {
		out = append(out, x)
	}
	for _, x := range p.CRoles {
		out = append(out, x)
	}
	for _, x := range p.Roles {
		out = append(out, x)
	}
	return out
}

// Load reads a package directory and checks it (Check); a package with problems isn't returned.
func Load(dir string) (*Package, error) {
	b, err := os.ReadFile(filepath.Join(dir, "plugin.yaml"))
	if err != nil {
		return nil, err
	}
	docs, err := yamlDocs(b)
	if err != nil || len(docs) != 1 {
		return nil, fmt.Errorf("plugin.yaml: want one document (%v)", err)
	}
	p := &Package{Dir: dir}
	dec := json.NewDecoder(bytes.NewReader(docs[0]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p.Manifest); err != nil {
		return nil, fmt.Errorf("plugin.yaml: %w", err)
	}
	for _, f := range p.Manifest.Spec.Resources {
		if filepath.IsAbs(f) || strings.Contains(filepath.ToSlash(filepath.Clean(f)), "../") || f == ".." {
			return nil, fmt.Errorf("plugin.yaml: resource %q must be a file inside the package", f)
		}
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, err
		}
		docs, err := yamlDocs(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for i, d := range docs {
			obj, _, err := v1.Decode(d)
			if err != nil {
				return nil, fmt.Errorf("%s, document %d: %w", f, i+1, err)
			}
			if err := p.add(obj); err != nil {
				return nil, fmt.Errorf("%s, document %d: %w", f, i+1, err)
			}
		}
	}
	if errs := Check(p); len(errs) > 0 {
		return nil, fmt.Errorf("package %s:\n  %s", dir, strings.Join(errs, "\n  "))
	}
	return p, nil
}

func (p *Package) add(obj meta.Object) error {
	switch o := obj.(type) {
	case *v1.KindDefinition:
		p.Kinds = append(p.Kinds, o)
	case *v1.ValidationPolicy:
		p.VPols = append(p.VPols, o)
	case *v1.MutationPolicy:
		p.MPols = append(p.MPols, o)
	case *v1.ClusterRole:
		p.CRoles = append(p.CRoles, o)
	case *v1.Role:
		p.Roles = append(p.Roles, o)
	default:
		return fmt.Errorf("a package holds KindDefinitions, ValidationPolicies, MutationPolicies, ClusterRoles and Roles, not %s", obj.GetTypeMeta().Kind)
	}
	return nil
}

// BinaryPath is the controller program's path in the package.
func (p *Package) BinaryPath() string { return filepath.Join(p.Dir, p.Manifest.Spec.Controller.Binary) }

func yamlDocs(b []byte) ([][]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
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
		j, err := json.Marshal(doc)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
}

var (
	pluginNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	versionRE    = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)
)

// ValidName says whether a plugin name is good: lower-case letters, digits and -, starting with a
// letter, at most 31 characters.
func ValidName(n string) bool { return pluginNameRE.MatchString(n) }

// forbidden are resources a plugin's roles can't reach: they would let it grant itself more
// (RBAC, tokens), change what the API serves or admits, or touch other plugins.
var forbidden = []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings", "serviceaccounts/token",
	"kinddefinitions", "validationpolicies", "mutationpolicies", "plugins", "plugins/status"}

// forbiddenVerbs on a resource: secrets' values and every approval are people's.
var forbiddenVerbs = map[string][]string{"secrets": {v1.VerbReadValue, v1.VerbApprove}, v1.ResourceExposure: {v1.VerbApprove}}

// Check says everything wrong with a package: its manifest, its objects' names, policies that
// reach beyond the package's own kinds, and roles that would give its controller powers no
// plugin gets (never cluster-admin, never RBAC).
func Check(p *Package) []string {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	m := p.Manifest
	if m.APIVersion != v1.APIVersion || m.Kind != "PluginPackage" {
		add("plugin.yaml: want apiVersion %s, kind PluginPackage", v1.APIVersion)
	}
	name := m.Metadata.Name
	if !ValidName(name) {
		add("plugin.yaml: metadata.name %q: lower-case letters, digits and -, starting with a letter, at most 31", name)
	}
	if !versionRE.MatchString(m.Spec.Version) {
		add("plugin.yaml: spec.version %q: want a semantic version (0.1.0)", m.Spec.Version)
	}
	if m.Spec.Controller.Binary == "" {
		add("plugin.yaml: spec.controller.binary: the controller's program (a file in the package)")
	}
	own := map[string]bool{} // the package's kinds, by every name a policy may use
	seen := map[string]bool{}
	for _, k := range p.Kinds {
		if seen["KindDefinition/"+k.Name] {
			add("KindDefinition %s: twice in the package", k.Name)
		}
		seen["KindDefinition/"+k.Name] = true
		own[k.Spec.Resource()] = true
	}
	checkMatch := func(kind, pname string, match v1.PolicyMatch) {
		if !strings.HasPrefix(pname, name+"-") {
			add("%s %s: name it %s-… so it's clear whose it is", kind, pname, name)
		}
		if seen[kind+"/"+pname] {
			add("%s %s: twice in the package", kind, pname)
		}
		seen[kind+"/"+pname] = true
		if len(match.Kinds) == 0 {
			add("%s %s: match.kinds must name the package's kinds", kind, pname)
		}
		for _, k := range match.Kinds {
			if !own[k] {
				add("%s %s: match.kinds %q: a plugin's policies apply only to the kinds it defines (by resource: %s)", kind, pname, k, strings.Join(slices.Sorted(maps.Keys(own)), ", "))
			}
		}
	}
	for _, x := range p.VPols {
		checkMatch("ValidationPolicy", x.Name, x.Spec.Match)
	}
	for _, x := range p.MPols {
		checkMatch("MutationPolicy", x.Name, x.Spec.Match)
	}
	checkRules := func(kind, rname string, rules []v1.PolicyRule) {
		if !strings.HasPrefix(rname, name+"-") {
			add("%s %s: name it %s-… so it's clear whose it is", kind, rname, name)
		}
		if seen[kind+"/"+rname] {
			add("%s %s: twice in the package", kind, rname)
		}
		seen[kind+"/"+rname] = true
		if len(rules) == 0 {
			add("%s %s: no rules", kind, rname)
		}
		for i, r := range rules {
			for _, e := range RuleProblems(r) {
				add("%s %s: rules[%d]: %s", kind, rname, i, e)
			}
		}
	}
	for _, r := range p.CRoles {
		checkRules("ClusterRole", r.Name, r.Rules)
	}
	for _, r := range p.Roles {
		checkRules("Role", r.Name, r.Rules)
		if r.Namespace == "" {
			add("Role %s: needs metadata.namespace (or make it a ClusterRole)", r.Name)
		}
	}
	return errs
}

// RuleProblems says why a plugin's role can't have a rule.
func RuleProblems(r v1.PolicyRule) []string {
	var errs []string
	if len(r.Verbs) == 0 || len(r.Resources) == 0 {
		errs = append(errs, "needs verbs and resources")
	}
	if slices.Contains(r.Verbs, "*") {
		errs = append(errs, "verbs: * isn't for plugins: name each verb")
	}
	for _, res := range r.Resources {
		switch {
		case res == "*" || strings.HasSuffix(res, "/*"):
			errs = append(errs, "resources: * isn't for plugins: name each resource")
		case slices.Contains(forbidden, res):
			errs = append(errs, fmt.Sprintf("resources: %s: a plugin's controller never gets it (it could give itself more, or change what the API admits)", res))
		}
		for _, v := range forbiddenVerbs[res] {
			if slices.Contains(r.Verbs, v) {
				errs = append(errs, fmt.Sprintf("%s on %s is for people, never a plugin", v, res))
			}
		}
	}
	return errs
}
