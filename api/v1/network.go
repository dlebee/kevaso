package v1

import "slices"

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
	LBIPPool   = "ip-pool"   // an address of its own: an IP from the host's extra addresses (spec.network.addresses)
)

// Egress sources: which address a silo's outgoing traffic leaves from.
const (
	EgressHost          = "host"          // the host's main address (default)
	EgressSameAsService = "sameAsService" // the address the silo is reached on
	EgressPool          = "pool"          // an address of its own: an IP of class ip-pool (egress.ip)
)

// SiloService is a silo's own service.
type SiloService struct {
	Ports        []ServicePort     `json:"ports,omitempty"`
	Expose       string            `json:"expose,omitempty"` // private | hostPort | loadBalancer
	HostPort     *HostPortSpec     `json:"hostPort,omitempty"`
	LoadBalancer *LoadBalancerSpec `json:"loadBalancer,omitempty"`
	// Lease: some exposed ports open only on a lease (design §7.2d).
	Lease *ServiceLease `json:"lease,omitempty"`
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
	Class string `json:"class"`
	// IP names the IP object (design §7.2c-1) whose address this is. Empty: one is made for the
	// service, named after the silo, that goes with it unless kept (kvo ip keep). worker-ip has none:
	// its address is the host's.
	IP        string   `json:"ip,omitempty"`
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
	// IP is the IP (class ip-pool) to send from with source pool; empty: the service's, when its
	// load balancer is ip-pool.
	IP string `json:"ip,omitempty"`
}

// SiloServiceStatus says where the service is reachable.
type SiloServiceStatus struct {
	Name     string `json:"name,omitempty"`     // its private name, e.g. api.payments.kevaso
	PublicIP string `json:"publicIP,omitempty"` // the outside address, if exposed: the address in
	EgressIP string `json:"egressIP,omitempty"` // where its outgoing traffic comes from: the address out
	// EgressNote says why the address out isn't the address in, when it isn't (design §7.2b).
	EgressNote string `json:"egressNote,omitempty"`
	// IP is the IP object the service's address is, when it has one (design §7.2c-1).
	IP string `json:"ip,omitempty"`
	// HostAddresses are the host's own extra addresses this silo holds (IPs of class ip-pool, in or
	// out): the host puts them on its uplink.
	HostAddresses []string `json:"hostAddresses,omitempty"`
	// NodePorts: for load-balancer classes that send to the host on ports of their own, which
	// host port each service port arrives on (the host forwards it to the silo), and from where.
	NodePorts    []NodePort `json:"nodePorts,omitempty"`
	SourceRanges []string   `json:"sourceRanges,omitempty"`
	// Announce: the public address is routed to the silo's host, which puts it on its loopback
	// (a shared IP announced over BGP).
	Announce bool `json:"announce,omitempty"`
}

// NodePort is the host port a service port arrives on from a load balancer.
type NodePort struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	NodePort int    `json:"nodePort"`
}

// Equal reports whether two service statuses are the same.
func (a SiloServiceStatus) Equal(b SiloServiceStatus) bool {
	if a.Name != b.Name || a.PublicIP != b.PublicIP || a.EgressIP != b.EgressIP || a.EgressNote != b.EgressNote || a.IP != b.IP || a.Announce != b.Announce ||
		len(a.NodePorts) != len(b.NodePorts) || len(a.SourceRanges) != len(b.SourceRanges) || !slices.Equal(a.HostAddresses, b.HostAddresses) {
		return false
	}
	for i := range a.NodePorts {
		if a.NodePorts[i] != b.NodePorts[i] {
			return false
		}
	}
	for i := range a.SourceRanges {
		if a.SourceRanges[i] != b.SourceRanges[i] {
			return false
		}
	}
	return true
}

// NodePort range: like Kubernetes'.
const (
	NodePortMin = 30000
	NodePortMax = 32767
)

// IsBuiltinLB says whether a load-balancer class is built in (the others come from plugins).
func IsBuiltinLB(class string) bool { return class == LBWorkerIP || class == LBIPPool }

// PluginLB is the silo's plugin load-balancer class ("" if it has none).
func PluginLB(s *Silo) string {
	sv := s.Spec.Service
	if sv == nil || sv.Expose != ExposeLoadBalancer || sv.LoadBalancer == nil || IsBuiltinLB(sv.LoadBalancer.Class) {
		return ""
	}
	return sv.LoadBalancer.Class
}

// VolumeLocal is the built-in storage class (the host's own disk).
const VolumeLocal = "local"

// PluginVolumes are the silo's volumes on a plugin's storage class, and its root disk's volume
// when spec.disk.class is one (DiskVolume).
func PluginVolumes(s *Silo) []Volume {
	var out []Volume
	for _, v := range s.Spec.Volumes {
		if v.Class != "" && v.Class != VolumeLocal {
			out = append(out, v)
		}
	}
	if d, ok := DiskVolume(s); ok {
		out = append(out, d)
	}
	return out
}

// RootDiskVolume names the volume that keeps a VM silo's own disk (an image file) when its
// spec.disk.class is a plugin's mount class. No volume a person names can be called that.
const RootDiskVolume = "disk.root"

// DiskVolume is the volume holding a cloud-hypervisor silo's root disk on a plugin's class
// (spec.disk.class), sized like the disk; ok is false for a local disk.
func DiskVolume(s *Silo) (Volume, bool) {
	c := s.Spec.Disk.Class
	if s.Spec.Runtime != "cloud-hypervisor" || c == "" || c == VolumeLocal {
		return Volume{}, false
	}
	return Volume{Name: RootDiskVolume, Class: c, Size: s.Spec.Disk.Size, Important: true}, true
}
