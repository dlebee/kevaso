// Package kplugin is how a provider plugin (design §12: KLB, KSI controller side, KDNS) talks to the
// control plane: gRPC over a unix socket (kpluginpb/kplugin.proto), like CSI. A plugin is its own process (its own
// systemd unit, holding its cloud token alone); the control plane finds it by its socket in
// /run/kevaso-plugins/NAME/plugin.sock, asks Info, and from then on calls it for the classes it
// provides.
//
// A plugin implements Plugin plus any of HostDescriber, LoadBalancers, Volumes and DNS, and serves
// them with Serve. The control plane uses Client. Every call is idempotent and keyed by an ID the
// control plane chooses (a silo's UID and a name), so it may repeat any call after a crash.
//
// Long operations (a volume detaching) never block a call for long: the plugin starts them, waits a
// little, and answers ErrInProgress if they aren't done; the control plane calls again later.
package kplugin

import (
	"context"
	"errors"
)

// Protocol is the protocol version this package speaks.
const Protocol = "kevaso.plugin/v1"

// Dir is where plugins put their sockets: Dir/NAME/plugin.sock.
const Dir = "/run/kevaso-plugins"

// Info is what a plugin is and provides.
type Info struct {
	Name     string `json:"name"` // e.g. linode
	Version  string `json:"version,omitempty"`
	Protocol string `json:"protocol"`
	// Hosts: the plugin recognises its own machines among the cluster's hosts (DescribeHosts).
	Hosts bool `json:"hosts,omitempty"`
	// LoadBalancers and Storage are the classes it serves; DNS the DNS provider names.
	LoadBalancers []Class  `json:"loadBalancers,omitempty"`
	Storage       []Class  `json:"storage,omitempty"`
	DNS           []string `json:"dns,omitempty"`
}

// Class is one load-balancer or storage class.
type Class struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// OwnHostsOnly: only hosts this plugin recognises (DescribeHosts) can use it, in the region the
	// address or volume is in.
	OwnHostsOnly bool `json:"ownHostsOnly,omitempty"`
	// Announce (load balancers): the address is routed to whichever host has the silo; that host
	// puts it on its loopback and the plugin's node side announces it (BGP).
	Announce bool `json:"announce,omitempty"`
	// NodePorts (load balancers): the load balancer sends to each backend host on a port of its own
	// (a node port), which the host forwards to the silo.
	NodePorts bool `json:"nodePorts,omitempty"`
}

// Host is a cluster host, as the control plane knows it.
type Host struct {
	Name    string `json:"name"`
	Address string `json:"address"` // its public address (Host spec.address)
}

// HostInfo is what a plugin knows about one of its own machines.
type HostInfo struct {
	Name           string `json:"name"`                     // the Host's name
	ID             string `json:"id"`                       // the provider's ID for the machine
	Region         string `json:"region"`                   // the provider's region, e.g. ca-central
	PrivateAddress string `json:"privateAddress,omitempty"` // its private address in the region, if any
}

// LoadBalancer is an address from a load-balancer class for one silo's service.
type LoadBalancer struct {
	Class     string `json:"class"`
	ID        string `json:"id"` // stable: the silo's UID
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Address asks for a specific address (classes that let you pick one, e.g. a shared IP).
	Address string `json:"address,omitempty"`
	Ports   []Port `json:"ports"`
	// Backends are where traffic goes: the silo's host. Hosts are every host of the plugin's in
	// the cluster (an announced address is shared with all of them, so it can follow the silo).
	Backends []HostInfo `json:"backends"`
	Hosts    []HostInfo `json:"hosts,omitempty"`
}

// Port is one service port and, for NodePorts classes, the backend port the host forwards.
type Port struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // TCP | UDP
	Port     int    `json:"port"`
	NodePort int    `json:"nodePort,omitempty"`
}

// LoadBalancerStatus is where the load balancer is.
type LoadBalancerStatus struct {
	Address string `json:"address"`
	// SourceRanges are where the load balancer connects to the hosts from (NodePorts classes): the
	// host only forwards node ports from these.
	SourceRanges []string `json:"sourceRanges,omitempty"`
}

// LoadBalancerRef names a load balancer to delete.
type LoadBalancerRef struct {
	Class   string `json:"class"`
	ID      string `json:"id"`
	Address string `json:"address,omitempty"`
}

// Volume is a block volume for one silo's volume.
type Volume struct {
	Class     string `json:"class"`
	ID        string `json:"id"`   // stable: the silo's UID and the volume's name
	Name      string `json:"name"` // a label for humans (provider side), e.g. payments-db-data
	SizeBytes int64  `json:"sizeBytes"`
	Region    string `json:"region"` // where to create it (the silo's host's)
}

// VolumeStatus is a created volume.
type VolumeStatus struct {
	Handle    string `json:"handle"` // the provider's ID for it
	Region    string `json:"region"`
	SizeBytes int64  `json:"sizeBytes,omitempty"`
}

// Attachment attaches a volume to a host, or detaches it.
type Attachment struct {
	Class  string   `json:"class"`
	Handle string   `json:"handle"`
	Host   HostInfo `json:"host"`
}

// AttachmentStatus is where the attached volume shows up on the host.
type AttachmentStatus struct {
	Device string `json:"device"` // a stable path, e.g. /dev/disk/by-id/scsi-0Linode_Volume_…
}

// VolumeRef names a volume to delete.
type VolumeRef struct {
	Class  string `json:"class"`
	Handle string `json:"handle"`
}

// Record is a DNS record set: every value of one name and type.
type Record struct {
	Provider string   `json:"provider"`
	Name     string   `json:"name"` // fully qualified, without the trailing dot
	Type     string   `json:"type"` // A | AAAA | TXT
	Values   []string `json:"values"`
	TTL      int      `json:"ttl,omitempty"`
	// Owner marks the record as this cluster's (e.g. kevaso:CLUSTER/ingress/NAMESPACE/NAME): a
	// plugin never changes or deletes a record set someone else owns.
	Owner string `json:"owner"`
}

// Plugin is every plugin.
type Plugin interface {
	Info(ctx context.Context) (Info, error)
}

// HostDescriber recognises the plugin's own machines among hosts; hosts it doesn't know are left out.
type HostDescriber interface {
	DescribeHosts(ctx context.Context, hosts []Host) ([]HostInfo, error)
}

// LoadBalancers serves load-balancer classes.
type LoadBalancers interface {
	EnsureLoadBalancer(ctx context.Context, lb LoadBalancer) (LoadBalancerStatus, error)
	DeleteLoadBalancer(ctx context.Context, ref LoadBalancerRef) error
}

// Volumes serves storage classes (the controller side: create, attach through the API). The host
// side (format once, mount) is the worker's.
type Volumes interface {
	EnsureVolume(ctx context.Context, v Volume) (VolumeStatus, error)
	AttachVolume(ctx context.Context, a Attachment) (AttachmentStatus, error)
	DetachVolume(ctx context.Context, a Attachment) error
	DeleteVolume(ctx context.Context, ref VolumeRef) error
}

// DNS serves DNS providers.
type DNS interface {
	EnsureRecord(ctx context.Context, r Record) error
	DeleteRecord(ctx context.Context, r Record) error
}

// Errors a plugin answers with; the client returns errors that match them with errors.Is.
var (
	// ErrInProgress: started, not done yet; call again later.
	ErrInProgress = errors.New("in progress")
	// ErrNotFound: no such thing (deleting it is then done).
	ErrNotFound = errors.New("not found")
	// ErrUnsupported: the plugin doesn't serve that (class, interface).
	ErrUnsupported = errors.New("unsupported")
	// ErrConflict: someone else's (a DNS record set with another owner, an address in use).
	ErrConflict = errors.New("conflict")
)
