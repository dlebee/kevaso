package v1

import (
	"time"

	"kevaso.com/core/api/meta"
)

// Secrets and Grants (design §8). A Secret holds one value, encrypted at rest with envelope
// encryption; the API never returns it, except through /value to someone with read-value, and
// never for a write-only secret. A Grant says what a silo may reach and use, and how a secret
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

// Secret is one secret value. Namespaced.
type Secret struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            SecretSpec   `json:"spec,omitempty"`
	Status          SecretStatus `json:"status,omitempty"`
}

// SecretSpec is the secret's rules. Value is write-only: it's sealed and removed before the
// object is stored, so reads never carry it.
type SecretSpec struct {
	Type string `json:"type,omitempty"` // opaque (default) | ed25519 | ecdsa-p256 | registry
	// Server and Username: a registry secret's registry host (e.g. ghcr.io) and user; the value is
	// the password or token.
	Server   string `json:"server,omitempty"`
	Username string `json:"username,omitempty"`
	// AllowedDelivery restricts how Grants may deliver it, whatever they ask (default: every
	// mode the type supports; signing keys only allow sign).
	AllowedDelivery []string `json:"allowedDelivery,omitempty"`
	// ValueReadable false makes the secret write-only: nobody can read the value back, not even
	// admins (default true for opaque secrets, false for registry secrets, always false for
	// signing keys).
	ValueReadable *bool `json:"valueReadable,omitempty"`
	// Generate asks the server to make the value: a random 32-byte token (opaque) or a new
	// private key. Nobody ever sees a generated signing key.
	Generate  bool       `json:"generate,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"` // when the value stops working; kvo warns before
	Value     []byte     `json:"value,omitempty"`     // write-only (base64 in JSON)
}

// SecretStatus is what the server records about the value, never the value itself.
type SecretStatus struct {
	Version   int64      `json:"version,omitempty"` // bumps on every new value: rotation
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
	Size      int        `json:"size,omitempty"`
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

// GrantSecret lets a silo use one secret, delivered one way.
type GrantSecret struct {
	Name    string `json:"name"`
	Deliver string `json:"deliver,omitempty"` // broker (default) | inject | file | env
	// Inject: where and how the gate adds it.
	To *InjectTarget `json:"to,omitempty"`
	// File: the path in the silo (under /run/secrets by default: NAME).
	Path string `json:"path,omitempty"`
	// Env: the variable name (default: the secret's name, upper-cased, - → _).
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
