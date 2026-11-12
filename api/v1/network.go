package v1

import "kevaso.com/core/api/meta"

// Services and exposure (design §7.1–7.2b). Every silo can carry its own service: a stable private
// name on the mesh, ports, and optionally an outside address. Silo ↔ silo traffic is denied until
// the receiving silo's allowFrom (or a NetworkPolicy, later) opens it.

// Exposure kinds.
const (
	ExposePrivate      = "private"      // the default: reachable on the mesh by name, if allowFrom permits
	ExposeHostPort     = "hostPort"     // listed ports on the host's own public address
	ExposeLoadBalancer = "loadBalancer" // an address from a load-balancer class
)

// Load-balancer classes built in.
const (
	LBWorkerIP = "worker-ip" // the host's own address, the service's ports
	LBIPPool   = "ip-pool"   // an address of its own from an IPPool routed to the host
)

// Egress sources: which address a silo's outgoing traffic leaves from.
const (
	EgressHost          = "host"          // the host's main address (default)
	EgressSameAsService = "sameAsService" // the address the silo is reached on
	EgressPool          = "pool"          // an address of its own from an IPPool
)

// Service is a silo's own service.
type Service struct {
	Ports        []ServicePort     `json:"ports,omitempty"`
	Expose       string            `json:"expose,omitempty"` // private | hostPort | loadBalancer
	HostPort     *HostPortSpec     `json:"hostPort,omitempty"`
	LoadBalancer *LoadBalancerSpec `json:"loadBalancer,omitempty"`
}

// ServicePort is one port of a service.
type ServicePort struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"` // TCP (default) | UDP
}

// HostPortSpec opens ports on the host's address (layer 4, client IP preserved; E009).
type HostPortSpec struct {
	Ports     []string `json:"ports,omitempty"`     // names; default all
	AllowFrom []string `json:"allowFrom,omitempty"` // source CIDRs; default anywhere
}

// LoadBalancerSpec asks for an outside address from a class.
type LoadBalancerSpec struct {
	Class     string   `json:"class"`
	Pool      string   `json:"pool,omitempty"` // ip-pool: which IPPool
	StableIP  bool     `json:"stableIP,omitempty"`
	AllowFrom []string `json:"allowFrom,omitempty"`
}

// AllowFrom lets another silo reach some of this silo's ports.
type AllowFrom struct {
	Silo  string   `json:"silo"`            // NAME (same namespace) or NAMESPACE/NAME
	Ports []string `json:"ports,omitempty"` // names; default all
}

// SiloNetwork is a silo's outbound choices.
type SiloNetwork struct {
	Egress Egress `json:"egress,omitempty"`
}

// Egress picks the source address.
type Egress struct {
	Source string `json:"source,omitempty"` // host (default) | sameAsService | pool
	Pool   string `json:"pool,omitempty"`   // source: pool
}

// ServiceStatus says where the service is reachable.
type ServiceStatus struct {
	Name     string `json:"name,omitempty"`     // its private name, e.g. api.payments.kevaso
	PublicIP string `json:"publicIP,omitempty"` // the outside address, if exposed
	EgressIP string `json:"egressIP,omitempty"` // where its outgoing traffic comes from
	PoolIP   string `json:"poolIP,omitempty"`   // the address it holds from an IPPool (stable)
}

// IPPool is addresses routed to one host, for silos to have their own (design §7.2b).
type IPPool struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            IPPoolSpec `json:"spec"`
}

// IPPoolSpec lists the addresses and where they're routed.
type IPPoolSpec struct {
	Host      string   `json:"host"`
	Addresses []string `json:"addresses"` // IPv4 CIDRs or single addresses (IPv6 comes later)
}

// Which silo holds which address is on the silo (status.service.poolIP): kvo describe ippool
// lists them.
