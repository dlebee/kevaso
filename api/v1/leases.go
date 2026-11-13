package v1

import (
	"time"

	"kevaso.com/core/api/meta"
)

// Ports opened on a lease (design §7.2d). A silo's outside exposure (hostPort or loadBalancer) can
// say some of its ports are leased: closed until someone opens them for a while, closing by
// themselves when that time is up. A lease can need a person's yes, as an Approval with the use
// expose. Private silo-to-silo access (allowFrom) is never leased.

// ServiceLease is a silo service's `lease:`.
type ServiceLease struct {
	// Ports are the leased ports, by name (default: every exposed port).
	Ports []string `json:"ports,omitempty"`
	// Default is a lease's length when the ask names none; Max the longest this silo may ever get
	// (Go durations). No max: the control plane's default limit applies.
	Default string `json:"default,omitempty"`
	Max     string `json:"max,omitempty"`
	// Approval: each lease needs a person's yes first.
	Approval *ApprovalRule `json:"approval,omitempty"`
	// AllowFrom narrows the service's own sources while a lease is open (CIDRs); never wider.
	AllowFrom []string `json:"allowFrom,omitempty"`
}

// ApprovalForExpose is an Approval's use for a lease that needs a person's yes.
const ApprovalForExpose = "expose"

// VerbOpen lets a person (or a service account) open and close a silo's leased ports
// (resource silos/exposure); VerbApprove on silos/exposure lets a person answer its leases.
const VerbOpen = "open"

// ResourceExposure is the RBAC resource of a silo's outside exposure: open and approve apply to it,
// by the silo's name.
const ResourceExposure = "silos/exposure"

// Lease phases.
const (
	LeaseOpen    = "Open"    // the port is open until status.until (an extension may be pending)
	LeasePending = "Pending" // an ask waits for a person's yes (and the port is closed)
	LeaseClosed  = "Closed"  // its time was up, or someone closed it
	LeaseDenied  = "Denied"  // the last ask was denied
	LeaseExpired = "Expired" // the last ask's approval expired unanswered
)

// Lease is the state of one leased port of one silo: open until when, by whose ask, and any ask
// waiting for a yes. Namespaced; only the control plane writes them (asks go through the silo's
// broker or POST …/silos/NAME/open), people read them (kvo get leases).
type Lease struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            LeaseSpec   `json:"spec"`
	Status          LeaseStatus `json:"status,omitempty"`
}

// LeaseSpec is which port of which silo.
type LeaseSpec struct {
	Silo    string `json:"silo"`
	SiloUID string `json:"siloUID"`
	Port    string `json:"port"`
}

// LeaseStatus is where the lease stands.
type LeaseStatus struct {
	Phase string `json:"phase,omitempty"`
	// OpenedAt and Until: the port is open from OpenedAt until Until (a lease closed early has
	// Until set to when it closed).
	OpenedAt *time.Time `json:"openedAt,omitempty"`
	Until    *time.Time `json:"until,omitempty"`
	// RequestedBy asked for the current (or last) opening; ApprovedBy said yes, if it needed one.
	RequestedBy string `json:"requestedBy,omitempty"`
	ApprovedBy  string `json:"approvedBy,omitempty"`
	// Pending is an ask waiting for a person's yes (an extension, while the port is open).
	Pending *LeaseAsk `json:"pending,omitempty"`
	// Reason says why it last changed (closed by whom, time up, denied, expired).
	Reason string `json:"reason,omitempty"`
}

// LeaseAsk is an ask waiting on an Approval.
type LeaseAsk struct {
	For         string    `json:"for"` // the lease's length once approved (already within limits)
	RequestedBy string    `json:"requestedBy"`
	RequestedAt time.Time `json:"requestedAt"`
	Approval    string    `json:"approval"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// LeaseOpenRequest is the body of POST …/silos/NAME/open (kvo open silo NAME --port P --for D) and
// …/close (Port only).
type LeaseOpenRequest struct {
	Port string `json:"port"`
	For  string `json:"for,omitempty"` // "" → the silo's lease.default
}

// IsOpen reports whether the lease opens its port, for the silo with uid siloUID, at now.
func (l *Lease) IsOpen(siloUID string, now time.Time) bool {
	return l != nil && l.Spec.SiloUID == siloUID && l.Status.Phase == LeaseOpen && l.Status.Until != nil && now.Before(*l.Status.Until)
}
