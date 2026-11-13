package client

import (
	"time"

	v1 "kevaso.com/core/api/v1"
)

// The secret broker (design §8.2): a host relays to the control plane (POST /agent/broker) what
// one of its silos asked its local endpoint (internal/agent/endpoint.go, ADR 0009), and asks for
// what it does for its silos itself (file and env deliveries, injections, panes it fetched). A
// request names a secret; which silo it's for is the host's to say, from where the silo's request
// arrived, never from the silo's words, and the control plane checks the silo is placed on that
// host. There's no call to list or search secrets, and no call returns a signing key.

// Ops a silo asks for (through its local endpoint).
const (
	OpGetSecret = "get-secret" // a value, for broker deliveries
	OpSign      = "sign"       // a signature; the key stays outside
	OpPublicKey = "public-key" // the public half of a key the silo may sign with
	OpPortOpen  = "port-open"  // open a leased port (Name) for a while (For) (design §7.2d)
	OpPortClose = "port-close" // close a leased port early
)

// Ops a host asks for its own silos (never forwarded from a silo): the file and env deliveries it
// writes into them (names and versions; with the values), the egress gate's injections and, for
// one that needs a person's yes, whether this request may have it (design §8.7), and the panes it
// fetched (design §10.1): a report, or an HTML pane's bundle (Payload; format: v1.PaneBundleMaxBytes).
const (
	OpDeliveries     = "deliveries"
	OpDeliveryValues = "delivery-values"
	OpInjections     = "injections"
	OpAskInject      = "ask-inject"
	OpPane           = "pane"
	OpPaneBundle     = "pane-bundle"
)

// OpPullCredential is a host's agent asking for the credential to pull one of its silos' images
// (Name: the image), from the silo's imagePull secret or its namespace's default for the image's
// registry. Never forwarded from a silo: the agent hands it to the engine for that one pull.
const OpPullCredential = "pull-credential"

// RegistryCredential is a registry secret, for one pull.
type RegistryCredential struct {
	Secret   string `json:"secret"`
	Server   string `json:"server"`
	Username string `json:"username"`
	Password []byte `json:"password"`
}

// BrokerRequest is one request, as the host relays it.
type BrokerRequest struct {
	Op      string `json:"op"`
	Name    string `json:"name,omitempty"`
	Payload []byte `json:"payload,omitempty"`
	Slot    *int64 `json:"slot,omitempty"`
	// For a secret that needs a person's yes (§8.7): how long access is wanted once approved and
	// how long to wait for an answer (Go durations; "" → the cluster's defaults), and the approval
	// this call is waiting on (asking again without it replaces the pending request).
	For      string `json:"for,omitempty"`
	Wait     string `json:"wait,omitempty"`
	Approval string `json:"approval,omitempty"`
	// pane: the report (its silo fields are filled in by the control plane, never taken from here).
	Pane *v1.PaneReport `json:"pane,omitempty"`
	// ask-inject: the request the gate would add the secret to.
	Host   string `json:"host,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

// BrokerResponse is the answer.
type BrokerResponse struct {
	Error string `json:"error,omitempty"`
	// Code says what kind of refusal Error is, for the endpoint's status: CodeNotFound, CodeConflict,
	// or "" (refused).
	Code       string      `json:"code,omitempty"`
	Value      []byte      `json:"value,omitempty"`
	Version    int64       `json:"version,omitempty"`
	Signature  []byte      `json:"signature,omitempty"`
	PublicKey  string      `json:"publicKey,omitempty"`
	Deliveries []Delivery  `json:"deliveries,omitempty"`
	Injections []Injection `json:"injections,omitempty"`
	// Registry: pull-credential, the credential (nil: none applies, pull anonymously).
	Registry *RegistryCredential `json:"registry,omitempty"`
	// Digest: pane-bundle, the name the bundle is stored under (sha256:…).
	Digest string `json:"digest,omitempty"`
	// Pending: the use waits for a person's yes. Ask again with Request.Approval set to its name.
	Pending *ApprovalWait `json:"pending,omitempty"`
	// port-open: the port is open until Until; Clamped, the time asked was more than its max.
	Until   *time.Time `json:"until,omitempty"`
	Clamped bool       `json:"clamped,omitempty"`
}

// Refusal codes.
const (
	CodeNotFound = "NotFound" // no such secret or key for this silo (whichever it really is)
	CodeConflict = "Conflict" // e.g. signing refused by slashing protection
)

// ApprovalWait is a pending approval a call waits on.
type ApprovalWait struct {
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Delivery is a secret the host writes into a silo as a file or an environment variable.
type Delivery struct {
	Name    string `json:"name"`
	Mode    string `json:"mode"` // file | env
	Path    string `json:"path,omitempty"`
	Env     string `json:"env,omitempty"`
	Version int64  `json:"version"`
	Value   []byte `json:"value,omitempty"` // delivery-values only
}

// Injection is a header the egress gate adds to a silo's requests to Host (or, on runtimes that
// inject themselves, a credential they swap in for a placeholder).
type Injection struct {
	Host    string `json:"host"`
	Header  string `json:"header"`
	Value   string `json:"value"`  // the formatted header value
	Raw     []byte `json:"raw"`    // the secret's value itself
	Format  string `json:"format"` // how Value was made from Raw, e.g. "Bearer {{value}}"
	Env     string `json:"env"`    // the variable a placeholder goes in (OpenShell)
	Secret  string `json:"secret"`
	Version int64  `json:"version"`
	// Approval: each request first needs a person's yes (ask with OpAskInject).
	Approval bool `json:"approval,omitempty"`
}

// AgentBrokerRequest is a host relaying a silo's request to the control plane
// (POST /agent/broker). The host is the caller's own (its certificate); the control plane checks
// the silo is placed on it.
type AgentBrokerRequest struct {
	Namespace string        `json:"namespace"`
	Name      string        `json:"name"`
	UID       string        `json:"uid"`
	Host      string        `json:"host,omitempty"` // only trusted from kevasod itself (one-host setups)
	Request   BrokerRequest `json:"request"`
}

// PathAgentBroker is where hosts relay broker requests.
const PathAgentBroker = "/agent/broker"

// ApprovalAnswer is the body of POST …/approvals/NAME/approve or /deny (optional).
type ApprovalAnswer struct {
	Reason string `json:"reason,omitempty"`
}
