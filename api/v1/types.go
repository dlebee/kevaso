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
}

// RuntimeStatus is one installed runtime's state on a worker.
type RuntimeStatus struct {
	State   string `json:"state"` // Installing | Ready | Failed
	Version string `json:"version,omitempty"`
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
	Placement   Placement    `json:"placement,omitempty"`
	Tolerations []Toleration `json:"tolerations,omitempty"`
}

// Resources a silo asks for.
type Resources struct {
	CPU    int    `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"` // e.g. 4Gi
}

// Placement narrows where a silo may run.
type Placement struct {
	HostSelector map[string]string `json:"hostSelector,omitempty"`
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
	Phase      string           `json:"phase,omitempty"` // Pending | Scheduled | Running | Stopped | Failed
	Host       string           `json:"host,omitempty"`  // where the scheduler placed it
	Conditions []meta.Condition `json:"conditions,omitempty"`
}
