// Package kri is the runtime interface: what every silo runtime (cloud-hypervisor, openshell,
// docker, podman, openshell-container) implements, so the worker agent drives them all the same way.
//
// Every operation is idempotent and keyed by ID: the agent reconciles towards what the API says,
// and may repeat any call after a crash or restart. A runtime reports its capabilities so admission
// and the scheduler never guess what it can do (design §6).
package kri

import (
	"context"
	"errors"
	"io"
	"net"
)

// ID names a silo on this host. UID makes a deleted and re-created silo a different one.
type ID struct {
	Namespace string
	Name      string
	UID       string
}

func (id ID) String() string { return id.Namespace + "/" + id.Name }

// Capabilities is what a runtime can do (design §6, "Rules that follow").
type Capabilities struct {
	Isolation       string // vm | container
	Network         string // nic | proxy | netns
	UDP             bool
	InboundServices bool
	Persistence     string // disk | volume
	Injection       bool   // injects credentials outside the silo itself
	Exec            bool
}

// Info identifies a runtime.
type Info struct {
	Name         string // e.g. cloud-hypervisor
	Version      string
	Capabilities Capabilities
}

// Spec is what to create.
type Spec struct {
	ID        ID
	Image     string
	CPU       int
	Memory    int64 // bytes
	DiskBytes int64
}

// State is where a silo is on this host.
type State string

const (
	Absent  State = "Absent"  // not on this host
	Created State = "Created" // exists, not running
	Running State = "Running"
	Stopped State = "Stopped"
	Failed  State = "Failed"
)

// Status is a silo's state on this host.
type Status struct {
	State   State
	Address string // private address, if it has one
	Message string
}

// ExecRequest runs a command inside a silo.
type ExecRequest struct {
	Command []string // argv; run directly, not through a shell
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// ErrNotFound: the silo isn't on this host.
var ErrNotFound = errors.New("silo not found on this host")

// Runtime is the interface every runtime implements.
type Runtime interface {
	Info() Info
	// Create makes the silo (disk, network, VM or container) without starting it. Creating one
	// that already exists with the same ID is a no-op.
	Create(ctx context.Context, spec Spec) error
	// Start starts a created or stopped silo; starting a running one is a no-op.
	Start(ctx context.Context, id ID) error
	// Stop stops it, keeping its disk; stopping a stopped one is a no-op.
	Stop(ctx context.Context, id ID) error
	// Delete removes it and everything it owns on this host; deleting an absent one is a no-op.
	Delete(ctx context.Context, id ID) error
	// Status reports it (State Absent if it isn't on this host).
	Status(ctx context.Context, id ID) (Status, error)
	// List returns every silo this runtime has on this host.
	List(ctx context.Context) ([]ID, error)
	// Exec runs a command inside a running silo and returns its exit code. ErrNotFound if absent.
	Exec(ctx context.Context, id ID, req ExecRequest) (int, error)
}

// Broker is a runtime that gives every silo its own channel to its host (vsock for VMs), so the
// host knows which silo is calling from the channel itself, never from what the silo says
// (design §8.2, research E014). The secret broker listens on it.
type Broker interface {
	// BrokerListen listens on port of id's channel. Every connection it accepts comes from that
	// silo and no other; the caller closes the listener when the silo goes.
	BrokerListen(id ID, port uint32) (net.Listener, error)
}
