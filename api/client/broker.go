package client

import "time"

// The secret broker (design §8.2): one protocol, JSON lines over the silo's own vsock channel to its
// host. A request names a secret; it never says which silo is asking, because the channel says.
// There's no call to list or search secrets, and no call returns a signing key.

// BrokerPort is the vsock port the broker listens on in every silo's channel.
const BrokerPort = 5000

// Broker operations a silo may ask for.
const (
	OpGetSecret  = "get-secret" // a value, for broker / file / env deliveries
	OpSign       = "sign"       // a signature; the key stays outside
	OpPublicKey  = "public-key" // the public half of a key the silo may sign with
	OpDeliveries = "deliveries" // which secrets go to files and env vars (names and versions only)
	OpWatch      = "watch"      // a stream of events: a secret or grant changed, re-read
	OpIngress    = "ingress"    // an ingress controller silo's routes, certificates and ACME answers
)

// Ops only a host's egress gate asks for its silos (never forwarded from a silo): the injections,
// and, for one that needs a person's yes, whether this request may have it (design §8.7).
const (
	OpInjections = "injections"
	OpAskInject  = "ask-inject"
)

// BrokerRequest is one line from a silo.
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
	// ask-inject: the request the gate would add the secret to.
	Host   string `json:"host,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

// BrokerResponse is one line back (watch: one per event).
type BrokerResponse struct {
	Error      string         `json:"error,omitempty"`
	Value      []byte         `json:"value,omitempty"`
	Version    int64          `json:"version,omitempty"`
	Signature  []byte         `json:"signature,omitempty"`
	PublicKey  string         `json:"publicKey,omitempty"`
	Deliveries []Delivery     `json:"deliveries,omitempty"`
	Injections []Injection    `json:"injections,omitempty"`
	Ingress    *IngressConfig `json:"ingress,omitempty"`
	Event      string         `json:"event,omitempty"` // watch: "changed" (a secret or grant), "ready"
	Secret     string         `json:"secret,omitempty"`
	// Pending: the use waits for a person's yes. Ask again with Request.Approval set to its name.
	Pending *ApprovalWait `json:"pending,omitempty"`
}

// ApprovalWait is a pending approval a call waits on.
type ApprovalWait struct {
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Delivery is a secret the guest helper writes to a file or an environment variable.
type Delivery struct {
	Name    string `json:"name"`
	Mode    string `json:"mode"` // file | env
	Path    string `json:"path,omitempty"`
	Env     string `json:"env,omitempty"`
	Version int64  `json:"version"`
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

// IngressConfig is what an ingress controller silo serves.
type IngressConfig struct {
	Routes []IngressRoute `json:"routes"`
	// Certs are certificate bundles (chain then key, PEM) for TLS hosts.
	Certs []IngressCert `json:"certs"`
	// Challenges are ACME HTTP-01 answers to serve on port 80 (token → key authorization).
	Challenges map[string]string `json:"challenges"`
}

// IngressRoute sends a host and path prefix to a backend.
type IngressRoute struct {
	Host    string `json:"host"`
	Path    string `json:"path"`
	Backend string `json:"backend"` // host:port, a private name
	TLS     bool   `json:"tls"`     // served on 443; port 80 redirects
	Ingress string `json:"ingress"` // namespace/name, for logs
}

// IngressCert is a certificate for some hosts.
type IngressCert struct {
	Hosts  []string `json:"hosts"`
	Bundle []byte   `json:"bundle"`
}

// ApprovalAnswer is the body of POST …/approvals/NAME/approve or /deny (optional).
type ApprovalAnswer struct {
	Reason string `json:"reason,omitempty"`
}
