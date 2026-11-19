package v1

import (
	"time"

	"kevaso.com/core/api/meta"
)

// A silo's restore phase, written by the control plane and never by a worker.
const (
	RestorePending = "pending" // waiting for hosts that have not reported
	RestoreSettled = "settled" // the placement is known; a worker may start it
	RestoreFrozen  = "frozen"  // two or more reported copies, or one the live stored host does not hold; placement stays until an operator settles it

	// CondFrozen is set on a silo while its restore is frozen. ReasonRestoreConflict is why.
	CondFrozen            = "Frozen"
	ReasonRestoreConflict = "RestoreConflict"
)

// RestoreGateName is the one cluster-scoped gate a restored history opens.
const RestoreGateName = "current"

// SiloRestore is the control plane's decision for one silo in one history.
// SettlingTo, while Phase stays frozen, is the host an operator placed the silo on.
// The chosen host starts nothing until Phase is settled. Since is the store revision
// of that placement: a holder's report counts only when its resourceVersion is newer.
type SiloRestore struct {
	History    string   `json:"history,omitempty"`
	Phase      string   `json:"phase,omitempty"` // pending | settled | frozen
	Holders    []string `json:"holders,omitempty"`
	SettlingTo string   `json:"settlingTo,omitempty"`
	Since      string   `json:"since,omitempty"`
}

// HostCopies is a host's report of the copies it holds in one history. Reported is set only
// after every runtime on that host answered.
type HostCopies struct {
	History  string         `json:"history,omitempty"`
	Reported bool           `json:"reported,omitempty"`
	Held     []HostHeldCopy `json:"held,omitempty"`
}

// HostHeldCopy is one silo a host's runtime has, running or kept stopped.
type HostHeldCopy struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	UID       string `json:"uid,omitempty"`
	Running   bool   `json:"running,omitempty"`
}

// RestoreGate is the account a restored history settles against. Required is the hosts the
// restored store had when the history began. HostsAdded are the hosts the operator says joined
// since the backup. ConfirmedOff are hosts the operator says are off or wiped.
type RestoreGate struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            RestoreGateSpec `json:"spec"`
}

// RestoreGateSpec is that account. Exactly one of NoHostsAdded and HostsAdded is a statement;
// neither, and nothing from before this history settles.
type RestoreGateSpec struct {
	History      string    `json:"history,omitempty"`
	Started      time.Time `json:"started,omitempty"`
	NoHostsAdded bool      `json:"noHostsAdded,omitempty"`
	HostsAdded   []string  `json:"hostsAdded,omitempty"`
	Required     []string  `json:"required,omitempty"`
	ConfirmedOff []string  `json:"confirmedOff,omitempty"`
}
