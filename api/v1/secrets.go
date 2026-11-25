package v1

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
)

// Secrets and Grants (design §8, hack/design/secret-keys.md). A Secret holds named keys, sealed
// together at rest with envelope encryption; the API never returns them, except through /value to
// someone with read-value, and never for a write-only secret. A Grant says what a silo may reach and use, and how a secret
// reaches it: the silo lists the Grants it uses (spec.grants).

// Secret types.
const (
	SecretOpaque    = "opaque"     // any bytes (a token, a password, a file)
	SecretEd25519   = "ed25519"    // a signing key: used through Sign only
	SecretECDSAP256 = "ecdsa-p256" // a signing key: used through Sign only
)

// Delivery modes: how a secret reaches a silo (design §8.5).
const (
	DeliverBroker = "broker" // the silo asks its local endpoint for it when it needs it
	DeliverInject = "inject" // the egress gate adds it to outgoing requests: never in the silo
	DeliverFile   = "file"   // a tmpfs file the host writes in the silo, rewritten on rotation
	DeliverEnv    = "env"    // an environment variable (written by the host): legacy apps only, flagged
	DeliverSign   = "sign"   // the silo asks for signatures: the key never leaves Kevaso
)

// Deliveries lists every delivery mode.
var Deliveries = []string{DeliverBroker, DeliverInject, DeliverFile, DeliverEnv, DeliverSign}

// Assurance levels a Grant can require (design §8.3).
const (
	AssuranceHost         = "host"
	AssuranceVTPM         = "vtpm"
	AssuranceConfidential = "confidential"
)

// ValueKey is the key spec.value stands for: `value: X` is `data: {value: X}`.
const ValueKey = "value"

// Secret is one secret: named keys. Namespaced.
type Secret struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            SecretSpec   `json:"spec,omitempty"`
	Status          SecretStatus `json:"status,omitempty"`
}

// SecretSpec is the secret's rules. Value, Data, SetData and RemoveKeys are write-only: the keys
// are sealed and the fields removed before the object is stored, so reads never carry them.
type SecretSpec struct {
	Type string `json:"type,omitempty"` // opaque (default) | ed25519 | ecdsa-p256 | registry
	// Server and Username: a registry secret's registry host (e.g. ghcr.io) and user; the key
	// value is the password or token.
	Server   string `json:"server,omitempty"`
	Username string `json:"username,omitempty"`
	// AllowedDelivery restricts how Grants may deliver it, whatever they ask (default: every
	// mode the type supports; signing keys only allow sign).
	AllowedDelivery []string `json:"allowedDelivery,omitempty"`
	// ValueReadable false makes the secret write-only: nobody can read the value back, not even
	// admins (default true for opaque secrets, false for registry secrets, always false for
	// signing keys).
	ValueReadable *bool `json:"valueReadable,omitempty"`
	// Generate asks the server to make the key value: a random 32-byte token (opaque) or a new
	// private key. Nobody ever sees a generated signing key.
	Generate  bool       `json:"generate,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"` // when the value stops working; kvo warns before
	// Value is shorthand for Data with the one key "value". Data replaces every key (a key left
	// out is removed). SetData adds or replaces the keys it names and keeps the others;
	// RemoveKeys removes keys. A write carries Value, Data, or SetData and RemoveKeys. All
	// write-only (base64 in JSON).
	Value      []byte            `json:"value,omitempty"`
	Data       map[string][]byte `json:"data,omitempty"`
	SetData    map[string][]byte `json:"setData,omitempty"`
	RemoveKeys []string          `json:"removeKeys,omitempty"`
}

// SecretStatus is what the server records about the value, never the value itself.
type SecretStatus struct {
	Version   int64      `json:"version,omitempty"` // bumps on every write of a value, whichever key: rotation
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
	Keys      []string   `json:"keys,omitempty"`      // the keys' names, sorted; never a value
	Size      int        `json:"size,omitempty"`      // every key's bytes
	PublicKey string     `json:"publicKey,omitempty"` // signing keys: hex (ed25519) or PKIX DER hex
}

// KeyType reports whether the secret is a signing key.
func (s *Secret) KeyType() bool {
	return s.Spec.Type == SecretEd25519 || s.Spec.Type == SecretECDSAP256
}

// Readable reports whether a person may ever read the value back.
func (s *Secret) Readable() bool {
	if s.KeyType() {
		return false
	}
	if s.Spec.Type == SecretRegistry {
		return s.Spec.ValueReadable != nil && *s.Spec.ValueReadable
	}
	return s.Spec.ValueReadable == nil || *s.Spec.ValueReadable
}

// Allows reports whether the secret may be delivered in mode.
func (s *Secret) Allows(mode string) bool {
	if s.Spec.Type == SecretRegistry {
		return false // only hosts' agents get it, for a pull: never a silo
	}
	if s.KeyType() && mode != DeliverSign {
		return false
	}
	if !s.KeyType() && mode == DeliverSign {
		return false
	}
	if len(s.Spec.AllowedDelivery) == 0 {
		return true
	}
	for _, m := range s.Spec.AllowedDelivery {
		if m == mode {
			return true
		}
	}
	return false
}

// Grant says what silos that list it may reach and use. Namespaced.
type Grant struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            GrantSpec `json:"spec"`
}

// GrantSpec is the grant's contents.
type GrantSpec struct {
	// Egress opens outbound traffic (silos reach nothing outside the cluster without it).
	Egress     []EgressRule     `json:"egress,omitempty"`
	Secrets    []GrantSecret    `json:"secrets,omitempty"`
	Operations *GrantOperations `json:"operations,omitempty"`
	Requires   *GrantRequires   `json:"requires,omitempty"`
}

// EgressRule opens outbound traffic to a destination. To is a CIDR (raw TCP/UDP, enforced by the
// host firewall) or a host name (TLS only, checked by the egress gate against the name the client
// asks for, so a name never opens more than itself).
type EgressRule struct {
	To        string   `json:"to"`
	Ports     []string `json:"ports,omitempty"`     // "443", "30000-30100"; default: all (CIDR), 443 (name)
	Protocols []string `json:"protocols,omitempty"` // tcp, udp; default tcp (names: tcp only)
}

// GrantSecret lets a silo use one secret (every key, or one), delivered one way.
type GrantSecret struct {
	Name string `json:"name"`
	// Key names one of the secret's keys; empty gives every key (inject: the secret's only key).
	Key     string `json:"key,omitempty"`
	Deliver string `json:"deliver,omitempty"` // broker (default) | inject | file | env
	// Inject: where and how the gate adds it.
	To *InjectTarget `json:"to,omitempty"`
	// File: with Key, the file's path (default /run/secrets/NAME/KEY); without, the file (a
	// secret holding only the key value) or the folder with a file per key (default
	// /run/secrets/NAME): FilePath.
	Path string `json:"path,omitempty"`
	// Env: with Key, the variable's name; without, the prefix of every key's variable (EnvName).
	Env string `json:"env,omitempty"`
	// Approval: each use waits for a person's yes (broker, inject; never file or env, §8.7).
	Approval *ApprovalRule `json:"approval,omitempty"`
}

// InjectTarget is a destination the gate adds a secret to.
type InjectTarget struct {
	Host   string `json:"host"`
	Header string `json:"header,omitempty"` // default Authorization
	Format string `json:"format,omitempty"` // default "Bearer {{value}}"
}

// GrantOperations are operations a silo may ask the broker for with keys that stay outside it.
type GrantOperations struct {
	Sign *SignOperation `json:"sign,omitempty"`
}

// SignOperation lets a silo ask for signatures with one key.
type SignOperation struct {
	KeyRef string `json:"keyRef"`
	// SlashingProtection refuses to sign a second, different payload for the same slot.
	SlashingProtection bool `json:"slashingProtection,omitempty"`
	// Approval: signing waits for a person's yes (§8.7).
	Approval *ApprovalRule `json:"approval,omitempty"`
}

// GrantRequires is what the asking silo must prove.
type GrantRequires struct {
	Assurance string `json:"assurance,omitempty"` // host (default) | vtpm | confidential
}

// cleanPathRE is a path an engine's mount argument can carry as it is: absolute, plain characters
// only (no comma, colon, equals, quote, space or control character: those split or extend the
// argument), no empty segment.
var cleanPathRE = regexp.MustCompile(`^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)

// CleanMountPath reports whether p is one clean absolute path: plain characters, no "." or ".."
// segment, not the root. Pure.
func CleanMountPath(p string) bool {
	if !cleanPathRE.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// ContainerFileProblem says why a file secret can't be delivered at p on a container silo (""
// if it can): it must be in a folder under /run, since the host mounts that folder into the
// container read-only (/run itself stays the container's own, writable tmpfs), and it must be a
// clean path (CleanMountPath), since it goes into the engine's mount argument. Pure.
func ContainerFileProblem(p string) string {
	switch {
	case !CleanMountPath(p) || !strings.HasPrefix(p, "/run/"):
		return p + " must be a clean path under /run/ (letters, digits, . _ - and / only)"
	case path.Dir(p) == "/run":
		return p + " must be in a folder under /run (like /run/secrets/NAME), not in /run itself: on a container the host mounts that folder read-only"
	}
	return ""
}

// keyRE is a key's name: letters, digits, - _ and ., starting and ending with a letter or a digit.
var keyRE = regexp.MustCompile(`^[A-Za-z0-9]([-_.A-Za-z0-9]{0,251}[A-Za-z0-9])?$`)

// ValidKey reports whether k may name a secret's key.
func ValidKey(k string) bool { return keyRE.MatchString(k) }

// envPart is a name upper-cased, - and . as _.
func envPart(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(s))
}

// KeyProblems says what's wrong with a set of key names (nil: nothing): each must be ValidKey,
// and no two may give the same variable name. Pure.
func KeyProblems(keys []string) []string {
	var out []string
	seen := map[string]string{}
	for _, k := range keys {
		if !ValidKey(k) {
			out = append(out, fmt.Sprintf("key %q: letters, digits, - _ and . (starting and ending with a letter or a digit), at most 253", k))
			continue
		}
		if o, ok := seen[envPart(k)]; ok {
			out = append(out, fmt.Sprintf("keys %q and %q give the same variable name (%s)", o, k, envPart(k)))
			continue
		}
		seen[envPart(k)] = k
	}
	return out
}

// EnvName is the variable key k of the secret gets (deliver: env): with the grant naming the key,
// its env if set; otherwise PREFIX_KEY, upper-cased with - and . as _, where PREFIX is the
// grant's env (without a key) or the secret's name, and the key "value" is PREFIX alone. Pure.
func (g GrantSecret) EnvName(k string) string {
	if g.Key != "" && g.Env != "" {
		return g.Env
	}
	prefix := envPart(g.Name)
	if g.Key == "" && g.Env != "" {
		prefix = g.Env
	}
	if k == ValueKey {
		return prefix
	}
	return prefix + "_" + envPart(k)
}

// SingleValue reports whether a secret's keys are just the shorthand's: the key value alone.
func SingleValue(keys []string) bool { return len(keys) == 1 && keys[0] == ValueKey }

// FilePath is where key k of a secret holding keys have is written (deliver: file). With the
// grant naming the key: its path (default /run/secrets/NAME/KEY). Without: a secret holding only
// the key value (SingleValue) is one file at its path (default /run/secrets/NAME); any other is a
// folder there, FOLDER/KEY. Pure.
func (g GrantSecret) FilePath(k string, have []string) string {
	switch {
	case g.Key != "" && g.Path != "":
		return g.Path
	case g.Key != "":
		return "/run/secrets/" + g.Name + "/" + k
	}
	p := g.Path
	if p == "" {
		p = "/run/secrets/" + g.Name
	}
	if SingleValue(have) {
		return p
	}
	return p + "/" + k
}

// Keys are the keys the grant gives of a secret holding keys: its one key, or every one. Pure.
func (g GrantSecret) Keys(have []string) []string {
	if g.Key == "" {
		return have
	}
	if slices.Contains(have, g.Key) {
		return []string{g.Key}
	}
	return nil
}

// InjectKey is the one key an inject delivers from a secret holding keys: the grant's, or the
// secret's only key ("" when it names none and the secret has several, or the key isn't there). Pure.
func (g GrantSecret) InjectKey(have []string) string {
	switch {
	case g.Key != "":
		if slices.Contains(have, g.Key) {
			return g.Key
		}
		return ""
	case len(have) == 1:
		return have[0]
	}
	return ""
}

// Delivery returns the secret's delivery mode, broker by default.
func (g GrantSecret) Delivery() string {
	if g.Deliver == "" {
		return DeliverBroker
	}
	return g.Deliver
}

// SecretNames lists every secret the grant names (secrets and keys for operations).
func (g *Grant) SecretNames() []string {
	var out []string
	for _, s := range g.Spec.Secrets {
		out = append(out, s.Name)
	}
	if g.Spec.Operations != nil && g.Spec.Operations.Sign != nil {
		out = append(out, g.Spec.Operations.Sign.KeyRef)
	}
	return out
}

// GrantsFor returns the grants a silo lists that exist, in its namespace, in the silo's order.
func GrantsFor(s *Silo, all []*Grant) []*Grant {
	var out []*Grant
	for _, name := range s.Spec.Grants {
		for _, g := range all {
			if g.Namespace == s.Namespace && g.Name == name {
				out = append(out, g)
				break
			}
		}
	}
	return out
}
