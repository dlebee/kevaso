package client

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
)

// OpInjections is what a host's egress gate asks for its silos (never forwarded from a silo).
const OpInjections = "injections"

// BrokerRequest is one line from a silo.
type BrokerRequest struct {
	Op      string `json:"op"`
	Name    string `json:"name,omitempty"`
	Payload []byte `json:"payload,omitempty"`
	Slot    *int64 `json:"slot,omitempty"`
}

// BrokerResponse is one line back (watch: one per event).
type BrokerResponse struct {
	Error      string      `json:"error,omitempty"`
	Value      []byte      `json:"value,omitempty"`
	Version    int64       `json:"version,omitempty"`
	Signature  []byte      `json:"signature,omitempty"`
	PublicKey  string      `json:"publicKey,omitempty"`
	Deliveries []Delivery  `json:"deliveries,omitempty"`
	Injections []Injection `json:"injections,omitempty"`
	Event      string      `json:"event,omitempty"` // watch: "changed" (a secret or grant), "ready"
	Secret     string      `json:"secret,omitempty"`
}

// Delivery is a secret the guest helper writes to a file or an environment variable.
type Delivery struct {
	Name    string `json:"name"`
	Mode    string `json:"mode"` // file | env
	Path    string `json:"path,omitempty"`
	Env     string `json:"env,omitempty"`
	Version int64  `json:"version"`
}

// Injection is a header the egress gate adds to a silo's requests to Host.
type Injection struct {
	Host    string `json:"host"`
	Header  string `json:"header"`
	Value   string `json:"value"` // the formatted header value
	Secret  string `json:"secret"`
	Version int64  `json:"version"`
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
