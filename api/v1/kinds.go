package v1

import (
	"encoding/json"
	"fmt"
	"sort"

	"kevaso.com/core/api/meta"
)

// KindInfo describes a built-in kind for the API server, clients and `kvo get kinds`.
type KindInfo struct {
	Kind    string
	Plural  string
	Scope   Scope
	New     func() meta.Object
	HasSpec bool // spec changes bump metadata.generation; status writes don't
	// ShortNames are what `kvo` also accepts, e.g. ns. The API paths use Plural only.
	ShortNames []string
}

var kinds = map[string]KindInfo{}

func register(k KindInfo) { kinds[k.Kind] = k }

func init() {
	register(KindInfo{Kind: "Namespace", Plural: "namespaces", ShortNames: []string{"ns"}, Scope: Cluster, New: func() meta.Object { return &Namespace{} }})
	register(KindInfo{Kind: "Host", Plural: "hosts", Scope: Cluster, HasSpec: true, New: func() meta.Object { return &Host{} }})
	register(KindInfo{Kind: "Silo", Plural: "silos", Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &Silo{} }})
	register(KindInfo{Kind: "Role", Plural: "roles", Scope: Namespaced, New: func() meta.Object { return &Role{} }})
	register(KindInfo{Kind: "RoleBinding", Plural: "rolebindings", Scope: Namespaced, New: func() meta.Object { return &RoleBinding{} }})
	register(KindInfo{Kind: "ClusterRole", Plural: "clusterroles", Scope: Cluster, New: func() meta.Object { return &ClusterRole{} }})
	register(KindInfo{Kind: "ClusterRoleBinding", Plural: "clusterrolebindings", Scope: Cluster, New: func() meta.Object { return &ClusterRoleBinding{} }})
	register(KindInfo{Kind: "IP", Plural: "ips", Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &IP{} }})
	register(KindInfo{Kind: "Secret", Plural: "secrets", Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &Secret{} }})
	register(KindInfo{Kind: "Grant", Plural: "grants", Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &Grant{} }})
	register(KindInfo{Kind: "IngressClass", Plural: "ingressclasses", Scope: Cluster, HasSpec: true, New: func() meta.Object { return &IngressClass{} }})
	register(KindInfo{Kind: "Ingress", Plural: "ingresses", ShortNames: []string{"ing"}, Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &Ingress{} }})
	register(KindInfo{Kind: "Issuer", Plural: "issuers", Scope: Cluster, HasSpec: true, New: func() meta.Object { return &Issuer{} }})
	register(KindInfo{Kind: "Certificate", Plural: "certificates", ShortNames: []string{"cert"}, Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &Certificate{} }})
	register(KindInfo{Kind: "Image", Plural: "images", ShortNames: []string{"img"}, Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &Image{} }})
	register(KindInfo{Kind: "SiloSet", Plural: "silosets", ShortNames: []string{"ss"}, Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &SiloSet{} }})
	register(KindInfo{Kind: "Service", Plural: "services", ShortNames: []string{"svc"}, Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &Service{} }})
	register(KindInfo{Kind: "Approval", Plural: "approvals", Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &Approval{} }})
	register(KindInfo{Kind: "Lease", Plural: "leases", Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &Lease{} }})
	register(KindInfo{Kind: "Pane", Plural: "panes", Scope: Namespaced, HasSpec: true, New: func() meta.Object { return &Pane{} }})
	register(KindInfo{Kind: "KindDefinition", Plural: "kinddefinitions", ShortNames: []string{"kd"}, Scope: Cluster, HasSpec: true, New: func() meta.Object { return &KindDefinition{} }})
	register(KindInfo{Kind: "ValidationPolicy", Plural: "validationpolicies", Scope: Cluster, HasSpec: true, New: func() meta.Object { return &ValidationPolicy{} }})
	register(KindInfo{Kind: "MutationPolicy", Plural: "mutationpolicies", Scope: Cluster, HasSpec: true, New: func() meta.Object { return &MutationPolicy{} }})
	register(KindInfo{Kind: "Plugin", Plural: "plugins", Scope: Cluster, HasSpec: true, New: func() meta.Object { return &Plugin{} }})
	register(KindInfo{Kind: "ServiceAccount", Plural: "serviceaccounts", ShortNames: []string{"sa"}, Scope: Namespaced, New: func() meta.Object { return &ServiceAccount{} }})
}

// Lookup finds a kind by its name ("Silo") or plural ("silos").
func Lookup(name string) (KindInfo, bool) {
	if k, ok := kinds[name]; ok {
		return k, true
	}
	for _, k := range kinds {
		if k.Plural == name {
			return k, true
		}
	}
	return KindInfo{}, false
}

// Kinds lists every built-in kind, sorted by name.
func Kinds() []KindInfo {
	out := make([]KindInfo, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// Decode parses a JSON object of any built-in kind, using its "kind" field. An object of a defined
// kind (apiVersion GROUP/VERSION, ADR 0005) decodes as *Unstructured, with a KindInfo that has only
// its Kind and New: its scope and resource are the server's to say (client.Resolve).
func Decode(data []byte) (meta.Object, KindInfo, error) {
	var tm meta.TypeMeta
	if err := json.Unmarshal(data, &tm); err != nil {
		return nil, KindInfo{}, fmt.Errorf("decode: %w", err)
	}
	if IsDefinedAPIVersion(tm.APIVersion) {
		u := &Unstructured{}
		if err := json.Unmarshal(data, u); err != nil {
			return nil, KindInfo{}, fmt.Errorf("decode %s %s: %w", tm.APIVersion, tm.Kind, err)
		}
		return u, KindInfo{Kind: tm.Kind, New: func() meta.Object { return &Unstructured{} }}, nil
	}
	if tm.APIVersion != APIVersion {
		return nil, KindInfo{}, fmt.Errorf("decode: apiVersion %q, want %q", tm.APIVersion, APIVersion)
	}
	k, ok := kinds[tm.Kind]
	if !ok {
		return nil, KindInfo{}, fmt.Errorf("decode: unknown kind %q", tm.Kind)
	}
	obj := k.New()
	if err := json.Unmarshal(data, obj); err != nil {
		return nil, KindInfo{}, fmt.Errorf("decode %s: %w", tm.Kind, err)
	}
	return obj, k, nil
}

// Clone returns a deep copy of any object (through JSON; fast enough until generated deep copies
// are worth it).
func Clone[T meta.Object](in T) (T, error) {
	var out T
	b, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	obj, _, err := Decode(b)
	if err != nil {
		return out, err
	}
	out, ok := obj.(T)
	if !ok {
		return out, fmt.Errorf("clone: decoded %T, want %T", obj, out)
	}
	return out, nil
}
