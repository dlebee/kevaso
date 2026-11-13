package v1

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"kevaso.com/core/api/meta"
)

// Kinds defined at runtime (design §4.2, ADR 0005): a KindDefinition names a new kind in a group
// its author owns (acme.dev), and the API server serves it like a built-in one.

// KindDefinition defines a kind. Cluster-scoped; its name is PLURAL.GROUP (databases.acme.dev),
// which is also the kind's resource: in roles, policies and the store.
type KindDefinition struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            KindDefinitionSpec `json:"spec"`
}

// KindDefinitionSpec is the kind.
type KindDefinitionSpec struct {
	// Group is a domain the author owns (acme.dev). Objects use apiVersion GROUP/VERSION.
	Group string `json:"group"`
	// Version is the one served version (v1). No conversion between versions.
	Version string    `json:"version"`
	Names   KindNames `json:"names"`
	Scope   Scope     `json:"scope"`
	// Schema describes the object's top-level fields other than apiVersion, kind and metadata.
	Schema       JSONSchema        `json:"schema"`
	Subresources *KindSubresources `json:"subresources,omitempty"`
	// PrinterColumns are what `kvo get` shows between NAME and AGE.
	PrinterColumns []PrinterColumn `json:"printerColumns,omitempty"`
}

// KindNames are the kind's names. Kind, Plural and the group can't change once defined.
type KindNames struct {
	Kind       string   `json:"kind"`               // Database
	Plural     string   `json:"plural"`             // databases
	Singular   string   `json:"singular,omitempty"` // database (default: kind in lower case)
	ShortNames []string `json:"shortNames,omitempty"`
}

// KindSubresources: with Status, status is written through /status only (controllers), and the main
// resource (people) never changes it.
type KindSubresources struct {
	Status *struct{} `json:"status,omitempty"`
}

// PrinterColumn is one column of `kvo get`.
type PrinterColumn struct {
	Name string `json:"name"`
	// JSONPath into the object: .spec.engine, .spec.items[0].name,
	// .status.conditions[?(@.type=="Ready")].status
	JSONPath string `json:"jsonPath"`
}

// HasStatus reports whether the kind has the status subresource.
func (s KindDefinitionSpec) HasStatus() bool {
	return s.Subresources != nil && s.Subresources.Status != nil
}

// Resource is PLURAL.GROUP.
func (s KindDefinitionSpec) Resource() string { return s.Names.Plural + "." + s.Group }

// APIVersion is GROUP/VERSION.
func (s KindDefinitionSpec) APIVersion() string { return s.Group + "/" + s.Version }

// JSONSchema is the OpenAPI v3 subset a KindDefinition's schema may use (ADR 0005). Anything else
// is refused.
type JSONSchema struct {
	Type        string `json:"type,omitempty"` // object | array | string | integer | number | boolean
	Description string `json:"description,omitempty"`

	Properties map[string]JSONSchema `json:"properties,omitempty"`
	Required   []string              `json:"required,omitempty"`
	// AdditionalProperties: a map whose values all have this schema (no properties then).
	AdditionalProperties *JSONSchema `json:"additionalProperties,omitempty"`
	Items                *JSONSchema `json:"items,omitempty"`

	Enum    []any `json:"enum,omitempty"`
	Default any   `json:"default,omitempty"`

	Minimum          *float64 `json:"minimum,omitempty"`
	Maximum          *float64 `json:"maximum,omitempty"`
	ExclusiveMinimum bool     `json:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum bool     `json:"exclusiveMaximum,omitempty"`
	MinLength        *int64   `json:"minLength,omitempty"`
	MaxLength        *int64   `json:"maxLength,omitempty"`
	Pattern          string   `json:"pattern,omitempty"`
	MinItems         *int64   `json:"minItems,omitempty"`
	MaxItems         *int64   `json:"maxItems,omitempty"`

	// PreserveUnknown keeps fields the schema doesn't list (otherwise they're refused).
	PreserveUnknown bool `json:"x-kevaso-preserve-unknown,omitempty"`
	// Validations are CEL rules on this node (`self`), like Kubernetes' x-kubernetes-validations.
	Validations []ValidationRule `json:"x-kevaso-validations,omitempty"`
}

// ValidationRule is a CEL expression that must be true, and what to say when it isn't.
type ValidationRule struct {
	Rule    string `json:"rule"`
	Message string `json:"message,omitempty"`
}

// ReservedGroup is the group of built-in kinds; it and kevaso.com (with its subdomains) are
// Kevaso's.
const ReservedGroup = "kevaso"

var (
	groupRE   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)+$`)
	versionRE = regexp.MustCompile(`^v[1-9][0-9]*$`)
	kindRE    = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
)

// ValidateGroup checks a defined kind's group: a lowercase domain with at least one dot, not
// Kevaso's own.
func ValidateGroup(g string) error {
	switch {
	case g == ReservedGroup || g == "kevaso.com" || strings.HasSuffix(g, ".kevaso.com"):
		return fmt.Errorf("group %q is Kevaso's: use a domain you own (e.g. acme.dev)", g)
	case len(g) > 253 || !groupRE.MatchString(g):
		return fmt.Errorf("group %q: want a lowercase domain with at least one dot (e.g. acme.dev)", g)
	}
	return nil
}

// ValidateVersion checks a defined kind's version: v1, v2, …
func ValidateVersion(v string) error {
	if !versionRE.MatchString(v) {
		return fmt.Errorf("version %q: want v1, v2, …", v)
	}
	return nil
}

// ValidateKindName checks a kind's name: CamelCase letters and digits, starting upper-case.
func ValidateKindName(k string) error {
	if !kindRE.MatchString(k) {
		return fmt.Errorf("kind %q: want letters and digits, starting with an upper-case letter (e.g. Database)", k)
	}
	return nil
}

// IsDefinedAPIVersion reports whether an apiVersion is a defined kind's (GROUP/VERSION with a
// group that has a dot), not a built-in's.
func IsDefinedAPIVersion(av string) bool {
	g, v, ok := strings.Cut(av, "/")
	return ok && strings.Contains(g, ".") && ValidateGroup(g) == nil && ValidateVersion(v) == nil
}

// ShadowsBuiltin reports whether a name a definition uses (kind, plural, singular or short name)
// is already a built-in kind's name, plural or short name, compared without case.
func ShadowsBuiltin(name string) (KindInfo, bool) {
	for _, k := range kinds {
		if strings.EqualFold(k.Kind, name) || strings.EqualFold(k.Plural, name) {
			return k, true
		}
		for _, s := range k.ShortNames {
			if strings.EqualFold(s, name) {
				return k, true
			}
		}
	}
	return KindInfo{}, false
}

// APIResource is one kind the API serves, built-in or defined: what `GET /apis` lists.
type APIResource struct {
	Group      string   `json:"group"`
	Version    string   `json:"version"`
	Kind       string   `json:"kind"`
	Plural     string   `json:"plural"`
	Singular   string   `json:"singular,omitempty"`
	ShortNames []string `json:"shortNames,omitempty"`
	Scope      Scope    `json:"scope"`
	// Resource is what RBAC and policies call it: the plural for built-ins, PLURAL.GROUP otherwise.
	Resource       string          `json:"resource"`
	Status         bool            `json:"status,omitempty"`
	BuiltIn        bool            `json:"builtIn,omitempty"`
	PrinterColumns []PrinterColumn `json:"printerColumns,omitempty"`
}

// APIVersion is the resource's GROUP/VERSION.
func (r APIResource) APIVersion() string { return r.Group + "/" + r.Version }

// APIResourceList is the body of `GET /apis`.
type APIResourceList struct {
	Resources []APIResource `json:"resources"`
}

// PathFor is the API path of a resource, in a namespace (or "" for all of them, or a
// cluster-scoped kind) and optionally one object.
func (r APIResource) PathFor(namespace, name string) string {
	p := "/apis/" + r.Group + "/" + r.Version + "/"
	if r.Scope == Namespaced && namespace != "" {
		p += "namespaces/" + escape(namespace) + "/"
	}
	p += r.Plural
	if name != "" {
		p += "/" + escape(name)
	}
	return p
}

func escape(s string) string { return url.PathEscape(s) }

// BuiltinResource describes a built-in kind as an APIResource.
func BuiltinResource(k KindInfo) APIResource {
	return APIResource{Group: ReservedGroup, Version: "v1", Kind: k.Kind, Plural: k.Plural, ShortNames: k.ShortNames,
		Scope: k.Scope, Resource: k.Plural, BuiltIn: true, Status: k.HasSpec}
}

// DefinedResource describes a defined kind as an APIResource.
func DefinedResource(d *KindDefinition) APIResource {
	s := d.Spec
	sing := s.Names.Singular
	if sing == "" {
		sing = strings.ToLower(s.Names.Kind)
	}
	return APIResource{Group: s.Group, Version: s.Version, Kind: s.Names.Kind, Plural: s.Names.Plural, Singular: sing,
		ShortNames: s.Names.ShortNames, Scope: s.Scope, Resource: s.Resource(), Status: s.HasStatus(), PrinterColumns: s.PrinterColumns}
}
