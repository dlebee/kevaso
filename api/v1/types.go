// Package v1 holds the kevaso/v1 kinds. M1 has the first three: Namespace, Host and Silo, with only
// the fields the next milestones use; more fields and kinds arrive milestone by milestone.
package v1

import (
	"time"

	"kevaso.com/core/api/meta"
)

// APIVersion of every built-in kind.
const APIVersion = "kevaso/v1"

// Scope says whether a kind lives in a namespace.
type Scope string

const (
	Namespaced Scope = "Namespaced"
	Cluster    Scope = "Cluster"
)

// ── Namespace ────────────────────────────────────────────────────────────────

// Namespace is the boundary for secrets, network, quotas and access. Cluster-scoped.
type Namespace struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Status          NamespaceStatus `json:"status,omitempty"`
}

// NamespaceStatus says whether the namespace is being deleted.
type NamespaceStatus struct {
	Phase string `json:"phase,omitempty"` // Active | Terminating
}

// ── Host ─────────────────────────────────────────────────────────────────────

// Host is a machine you brought and the components installed on it. Cluster-scoped.
type Host struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            HostSpec   `json:"spec"`
	Status          HostStatus `json:"status,omitempty"`
}

// HostSpec is what the operator declares.
type HostSpec struct {
	Address    string         `json:"address"`
	Components HostComponents `json:"components"`
	// Region and Zone say where the machine is (design §3.4): shown everywhere, used for placement.
	Region string `json:"region,omitempty"`
	Zone   string `json:"zone,omitempty"`
	// Unschedulable: no new silos land here (kvoadm host drain sets it; silos already here stay
	// unless drain moves them).
	Unschedulable bool `json:"unschedulable,omitempty"`
	// Network: how the mesh reaches this machine.
	Network HostNetwork `json:"network,omitempty"`
}

// HostNetwork is what the mesh needs to know about a machine's reachability (design §7).
type HostNetwork struct {
	// BehindNAT: nothing unsolicited reaches this machine (a box at home). It dials out to public
	// hosts; to other NAT'd hosts it goes through a relay, end-to-end encrypted.
	BehindNAT bool `json:"behindNAT,omitempty"`
	// ListenPort is the WireGuard port on Address (default 51820), for public hosts.
	ListenPort int `json:"listenPort,omitempty"`
}

// HostComponents are installed explicitly; there's no hidden all-in-one mode.
type HostComponents struct {
	ControlPlane *ControlPlaneSpec `json:"controlPlane,omitempty"`
	Worker       *WorkerSpec       `json:"worker,omitempty"`
}

// ControlPlaneSpec configures the control-plane component.
type ControlPlaneSpec struct {
	StateOnly bool `json:"stateOnly,omitempty"` // a light system node: store member only
}

// WorkerSpec is what a worker offers and what it repels.
type WorkerSpec struct {
	Labels   map[string]string `json:"labels,omitempty"`
	Runtimes []RuntimeSpec     `json:"runtimes,omitempty"`
	Taints   []Taint           `json:"taints,omitempty"`
}

// RuntimeSpec is one runtime installed on a worker, with its options.
type RuntimeSpec struct {
	Name    string            `json:"name"` // cloud-hypervisor | openshell | docker | podman | openshell-container
	Options map[string]string `json:"options,omitempty"`
}

// TaintEffect is what a taint does to silos that don't tolerate it. There's no NoExecute: silos are
// stateful, so a taint never evicts a running one.
type TaintEffect string

const (
	NoSchedule       TaintEffect = "NoSchedule"
	PreferNoSchedule TaintEffect = "PreferNoSchedule"
)

// Taint keeps silos away from a worker unless they tolerate it.
type Taint struct {
	Key    string      `json:"key"`
	Value  string      `json:"value,omitempty"`
	Effect TaintEffect `json:"effect"`
}

// HostStatus is what the host's agent reports.
type HostStatus struct {
	Conditions []meta.Condition `json:"conditions,omitempty"`
	// LastHeartbeat is when the host's agent last reported; host-loss detection (M5) reads it.
	LastHeartbeat *time.Time               `json:"lastHeartbeat,omitempty"`
	Runtimes      map[string]RuntimeStatus `json:"runtimes,omitempty"`
	// Allocatable is what the worker offers to silos (after what the host itself needs).
	Allocatable Resources `json:"allocatable,omitempty"`
	// Network is the host's place on the mesh: its index and addresses (assigned by the control
	// plane) and its WireGuard public keys (published by the host; private keys never leave it).
	Network NetworkStatus `json:"network,omitempty"`
	// Provider is what a provider plugin knows about this machine, if it's one of its own (a
	// Linode): the plugin's classes (volumes, load balancers) only reach such hosts.
	Provider *HostProvider `json:"provider,omitempty"`
}

// HostProvider is a machine as its provider sees it.
type HostProvider struct {
	Name           string `json:"name"`                     // the plugin, e.g. linode
	ID             string `json:"id"`                       // the provider's ID for the machine
	Region         string `json:"region"`                   // the provider's region, e.g. ca-central
	PrivateAddress string `json:"privateAddress,omitempty"` // its private address in the region
}

// NetworkStatus is a host's mesh identity.
type NetworkStatus struct {
	Index          int    `json:"index,omitempty"`          // 1…255, assigned once
	MeshIP         string `json:"meshIP,omitempty"`         // on kevaso0, e.g. 10.63.0.3
	SiloSubnet     string `json:"siloSubnet,omitempty"`     // its silos, e.g. 10.64.3.0/24
	PublicKey      string `json:"publicKey,omitempty"`      // kevaso0's WireGuard key
	InnerIP        string `json:"innerIP,omitempty"`        // behind NAT: on the end-to-end tunnel kevaso1
	InnerPublicKey string `json:"innerPublicKey,omitempty"` // kevaso1's key
}

// RuntimeStatus is one installed runtime's state on a worker.
type RuntimeStatus struct {
	State   string `json:"state"` // Installing | Ready | Failed
	Version string `json:"version,omitempty"`
	Message string `json:"message,omitempty"` // the install step while Installing, the error if Failed
}

// ── Silo ─────────────────────────────────────────────────────────────────────

// Silo is one isolated, stateful machine. Namespaced.
type Silo struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            SiloSpec   `json:"spec"`
	Status          SiloStatus `json:"status,omitempty"`
}

// SiloSpec is what the user declares.
type SiloSpec struct {
	Runtime     string       `json:"runtime"`
	Image       string       `json:"image,omitempty"`
	Resources   Resources    `json:"resources,omitempty"`
	Disk        Disk         `json:"disk,omitempty"`
	Placement   Placement    `json:"placement,omitempty"`
	Tolerations []Toleration `json:"tolerations,omitempty"`
	Init        *Init        `json:"init,omitempty"`
	// Availability says what happens when the silo's host is lost (design §0.3).
	Availability Availability `json:"availability,omitempty"`
	// Service is the silo's own service (design §7.1); AllowFrom opens it to other silos.
	Service   *Service    `json:"service,omitempty"`
	AllowFrom []AllowFrom `json:"allowFrom,omitempty"`
	Network   SiloNetwork `json:"network,omitempty"`
	// Grants are the Grant objects (in this namespace) the silo uses: what it may reach outside
	// the cluster and which secrets it gets, and how (design §8).
	Grants []string `json:"grants,omitempty"`
	// Volumes are extra storage, kept across stops and restarts; on containers they're what
	// persists (design §6).
	Volumes []Volume `json:"volumes,omitempty"`
	// Command is a container silo's main process (default: the image's own; for the ubuntu-24.04
	// image, which has none that stays up, a process that sleeps, so the silo is a machine to exec into).
	Command []string `json:"command,omitempty"`
}

// Volume is a silo's extra storage.
type Volume struct {
	Name      string `json:"name"`
	Class     string `json:"class,omitempty"` // default: local
	Size      string `json:"size,omitempty"`  // e.g. 10Gi (on container runtimes: not enforced yet)
	MountPath string `json:"mountPath"`
	Important bool   `json:"important,omitempty"` // never left behind by a Recreate
}

// Availability is the silo's answer to losing its host.
type Availability struct {
	// OnHostLoss: Wait (default: stay, down until the host is back), Recreate (a fresh instance from
	// the image on another host; data on host-local disks is lost, by declaration), or Move (with its
	// data; needs every disk on a movable storage class).
	OnHostLoss string `json:"onHostLoss,omitempty"`
}

// OnHostLoss policies.
const (
	OnHostLossWait     = "Wait"
	OnHostLossRecreate = "Recreate"
	OnHostLossMove     = "Move"
)

// Policy returns the silo's onHostLoss policy, Wait by default.
func (s *Silo) Policy() string {
	if s.Spec.Availability.OnHostLoss == "" {
		return OnHostLossWait
	}
	return s.Spec.Availability.OnHostLoss
}

// Disk is the silo's own disk.
type Disk struct {
	Class string `json:"class,omitempty"` // default: local
	Size  string `json:"size,omitempty"`  // e.g. 20Gi
}

// Init is the steps that run inside a silo before it's Ready (GitHub Actions-style).
type Init struct {
	When    string     `json:"when,omitempty"`    // firstBoot (default) | everyBoot
	Timeout string     `json:"timeout,omitempty"` // e.g. 15m
	Steps   []InitStep `json:"steps"`
}

// InitStep is one step: a script run as root, by a shell or any interpreter in the image.
type InitStep struct {
	Name  string `json:"name"`
	Shell string `json:"shell,omitempty"` // default: sh
	Run   string `json:"run"`
}

// StepStatus is how one init step went.
type StepStatus struct {
	Name     string `json:"name"`
	State    string `json:"state"` // Pending | Running | Done | Failed
	ExitCode *int   `json:"exitCode,omitempty"`
	Duration string `json:"duration,omitempty"`
}

// Resources a silo asks for.
type Resources struct {
	CPU    int    `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"` // e.g. 4Gi
}

// Placement narrows where a silo may run.
type Placement struct {
	HostSelector map[string]string `json:"hostSelector,omitempty"`
	Region       string            `json:"region,omitempty"` // only hosts in this region
	Zone         string            `json:"zone,omitempty"`   // only hosts in this zone
}

// Toleration lets a silo land on a worker with a matching taint. An empty Effect tolerates both effects.
type Toleration struct {
	Key    string      `json:"key"`
	Value  string      `json:"value,omitempty"`
	Effect TaintEffect `json:"effect,omitempty"`
}

// Tolerates reports whether the toleration covers the taint.
func (t Toleration) Tolerates(taint Taint) bool {
	return t.Key == taint.Key && (t.Value == "" || t.Value == taint.Value) &&
		(t.Effect == "" || t.Effect == taint.Effect)
}

// SiloStatus is what controllers report.
type SiloStatus struct {
	Phase      string           `json:"phase,omitempty"` // Pending | Scheduled | Starting | Running | Failed
	Host       string           `json:"host,omitempty"`  // where the scheduler placed it
	Conditions []meta.Condition `json:"conditions,omitempty"`
	Init       []StepStatus     `json:"init,omitempty"`
	Address    string           `json:"address,omitempty"` // the silo's private address
	Service    ServiceStatus    `json:"service,omitempty"`
	// Volumes are its volumes from a provider's storage class: where each is and whether it's
	// attached and mounted.
	Volumes []VolumeStatus `json:"volumes,omitempty"`
}

// VolumeStatus is one provider volume of a silo. The control plane creates and attaches it (Handle,
// Region, AttachedTo, Device); the host's agent formats it once and mounts it (Mounted).
type VolumeStatus struct {
	Name       string `json:"name"`
	Class      string `json:"class"`
	Handle     string `json:"handle,omitempty"`     // the provider's ID
	Region     string `json:"region,omitempty"`     // where it is: the silo stays in this region
	AttachedTo string `json:"attachedTo,omitempty"` // the host it's attached to
	Device     string `json:"device,omitempty"`     // its path on that host
	Mounted    bool   `json:"mounted,omitempty"`
	Message    string `json:"message,omitempty"` // what's going on, or what went wrong
}
