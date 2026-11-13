package v1

import (
	"time"

	"kevaso.com/core/api/meta"
)

// Approvals (design §8.7): a grant can say a secret, or a signing key, is used only after a person
// says yes. It's optional, per secret in a grant: without `approval`, the grant works as before.
// A use that needs a yes becomes an Approval, a pending request that always expires; the same
// silo asking for the same secret again replaces it. People answer with `kvo approve` / `kvo deny`
// (the RBAC verb approve on that secret); the silo that asks never can.

// VerbApprove lets a person answer approvals for a secret (by name or label, like the other
// secret verbs).
const VerbApprove = "approve"

// ApprovalRule is a grant's `approval:` on one secret or key.
type ApprovalRule struct {
	Required bool `json:"required,omitempty"`
}

// Approval phases.
const (
	ApprovalPending  = "Pending"
	ApprovalApproved = "Approved"
	ApprovalDenied   = "Denied"
	ApprovalExpired  = "Expired" // nobody answered in time
)

// What an approval is for (the broker op that asked).
const (
	ApprovalForSecret = "get-secret" // the value, over the broker
	ApprovalForSign   = "sign"       // signatures with a key
	ApprovalForInject = "inject"     // the egress gate adding the secret to requests
)

// Approval is one silo's request to use one secret. Namespaced. Only the control plane creates
// and changes them; people read them and answer.
type Approval struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            ApprovalSpec   `json:"spec"`
	Status          ApprovalStatus `json:"status,omitempty"`
}

// ApprovalSpec is what is asked.
type ApprovalSpec struct {
	Silo    string `json:"silo"`
	SiloUID string `json:"siloUID"`
	Secret  string `json:"secret"`
	// Port: an expose approval's leased port (its Secret is empty).
	Port  string `json:"port,omitempty"`
	Use   string `json:"use"`   // get-secret | sign | inject | expose
	Grant string `json:"grant"` // the grant that requires the yes
	// Inject: where the request goes. Sign: the payload's hash (hex SHA-256) and size.
	Destination *ApprovalDestination `json:"destination,omitempty"`
	PayloadHash string               `json:"payloadHash,omitempty"`
	Summary     string               `json:"summary,omitempty"`
	// For is how long access is wanted once approved (a Go duration, e.g. 30m).
	For string `json:"for"`
	// RequestedAt and ExpiresAt: the request expires unanswered at ExpiresAt. Always set.
	RequestedAt time.Time `json:"requestedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// ApprovalDestination is the request an injection was asked for.
type ApprovalDestination struct {
	Host   string `json:"host"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

// ApprovalStatus is the answer.
type ApprovalStatus struct {
	Phase      string     `json:"phase,omitempty"`
	AnsweredBy string     `json:"answeredBy,omitempty"`
	AnsweredAt *time.Time `json:"answeredAt,omitempty"`
	// AccessUntil: approved, the silo uses the secret without asking until then.
	AccessUntil *time.Time `json:"accessUntil,omitempty"`
	Reason      string     `json:"reason,omitempty"` // a deny's reason, if given
}

// NeedsApproval reports whether this grant's secret is used only after a person says yes.
func (g GrantSecret) NeedsApproval() bool { return g.Approval != nil && g.Approval.Required }

// NeedsApproval reports whether signing with this key needs a person's yes.
func (s *SignOperation) NeedsApproval() bool {
	return s != nil && s.Approval != nil && s.Approval.Required
}
