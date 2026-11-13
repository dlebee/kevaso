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
	"strings"
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
	Volumes   []Volume
	Command   []string // containers: the main process (empty: the image's)
	// DiskHostPath, if set, is a folder on the host (a mount class's volume, already mounted) that
	// keeps a VM's own disk as an image file instead of host-local storage, so the disk moves with
	// the silo. Only one host has it mounted at a time; the runtime reuses an image already there.
	DiskHostPath string
}

// Volume is extra storage mounted in the silo.
type Volume struct {
	Name      string
	MountPath string
	SizeBytes int64
	// HostPath, if set, is a folder on the host that already holds the volume (a provider's block
	// volume, mounted by the agent): the runtime binds it instead of making storage of its own.
	HostPath string
}

// VolumeSetter is a runtime whose silos' volumes are fixed while they run (a VM's disks and shares
// are set when its VMM starts; no hot-add). SetVolumes makes a silo's volumes vols for its next
// start: if it's running with others it changes nothing and says restart (the agent stops it and
// calls again); stopped or created, it applies them (restart false). Unchanged volumes: no work.
type VolumeSetter interface {
	SetVolumes(ctx context.Context, id ID, vols []Volume) (restart bool, err error)
}

// GuestVolumes is a runtime whose volumes the silo's own system mounts (a VM's guest: its disks and
// virtiofs shares at their mount paths, and again at every boot). The agent calls it once the silo
// runs, before its secrets are written and its init steps run; it is idempotent.
type GuestVolumes interface {
	MountGuestVolumes(ctx context.Context, id ID) error
}

// InitStep is one init step (design §0.2): a script run by a shell or any interpreter.
type InitStep struct {
	Name  string
	Shell string // default sh
	Run   string
}

// InitContainers is a runtime that runs a silo's init steps before its main process starts, each
// in a container of its own from the silo's image, with its network and volumes (design §0.2:
// containers map init to init containers). Runtimes without it run steps through Exec once running.
type InitContainers interface {
	RunInit(ctx context.Context, id ID, step InitStep, out io.Writer) (exitCode int, err error)
}

// HostSecrets is a runtime whose silos get their file and env secrets from the host with nothing
// written into them (containers, ADR 0009 addendum: files from a tmpfs of the host's, mounted
// read-only; variables in the engine's own config), instead of the agent writing them in through
// Exec. The agent calls SetSecrets before the silo starts (before its init containers too) and
// again whenever what it receives changes; Stop and Kill take the values out of the host's memory
// where the runtime can (the next start gets them again), Delete removes everything.
//
// A file changes in place while the silo runs. pending says what waits for its next start: an
// environment variable (a running process's environment can't be changed), or a file in a folder
// the running silo doesn't have mounted yet. "" when nothing waits.
type HostSecrets interface {
	SetSecrets(ctx context.Context, id ID, s Secrets) (pending string, err error)
}

// Secrets are a silo's file and env deliveries, with their values.
type Secrets struct {
	Files []SecretFile
	Env   []SecretEnv
}

// SecretFile is one secret as a file in the silo, owned by root.
type SecretFile struct {
	Secret  string
	Path    string // absolute, under /run/
	Mode    uint32 // e.g. 0o400
	Value   []byte
	Version int64
}

// SecretEnv is one secret as an environment variable of the silo's command.
type SecretEnv struct {
	Secret  string
	Name    string
	Value   []byte
	Version int64
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
	// TTY, if set, runs the command on a terminal: Stdout gets everything it prints, Stderr isn't
	// used, and the window follows TTY.Resize. Runtimes that can't make one return ErrNoTTY.
	TTY *TTY
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
	// When ctx is cancelled (the client went away) Exec stops the command inside the silo, not
	// only the runtime's own client, before it returns.
	Exec(ctx context.Context, id ID, req ExecRequest) (int, error)
}

// Killer is a runtime that can stop a silo at once, with no graceful shutdown (SIGKILL, not a stop
// with a grace period): what a fence does, since the silo is about to be started elsewhere and a
// clean shutdown isn't worth eating into that margin. Killing a stopped or absent one is a no-op.
type Killer interface {
	Kill(ctx context.Context, id ID) error
}

// Kill stops a silo at once where the runtime can (Killer), else as gracefully as Stop does.
func Kill(ctx context.Context, rt Runtime, id ID) error {
	if k, ok := rt.(Killer); ok {
		return k.Kill(ctx, id)
	}
	return rt.Stop(ctx, id)
}

// Resetter is a runtime that can put a silo back onto an image (design §0.2, `kvo reset`): a
// fresh disk or container from spec.Image, with the same ID and private address, and its volumes
// kept. The silo is stopped first (the agent stops it; Reset makes sure) and left Created. Every
// built-in runtime has it.
type Resetter interface {
	Reset(ctx context.Context, spec Spec) error
}

// ParseDiskImage reads a disk image reference (URL#sha256=HEX, as an Image version's disk reaches
// a VM runtime).
func ParseDiskImage(ref string) (url, sha256 string, ok bool) {
	i := strings.LastIndex(ref, "#sha256=")
	if i < 0 || !strings.HasPrefix(ref, "https://") {
		return "", "", false
	}
	return ref[:i], ref[i+len("#sha256="):], true
}

// Policied is a runtime that enforces a silo's grants itself (OpenShell: its policy engine and
// providers), instead of the host's firewall and egress gate.
type Policied interface {
	// SetPolicy makes the silo's policy exactly p. Idempotent: unchanged policy, no work.
	SetPolicy(ctx context.Context, id ID, p Policy) error
}

// Policy is what a silo may reach outside the cluster, and the credentials injected on the way.
type Policy struct {
	Egress      []Endpoint
	Credentials []Credential
}

// Endpoint is one destination: a host name ("api.github.com", "*.github.com") or one IPv4 address, and
// one TCP port.
type Endpoint struct {
	Host string
	Port int
}

// Credential is a secret the runtime injects for requests to Host. The silo sees only a placeholder
// in Env, which its programs send in Header; the runtime swaps the real value in.
type Credential struct {
	Name    string // the secret's name
	Env     string
	Host    string
	Header  string // e.g. Authorization
	Bearer  bool   // the header value is "Bearer <value>"
	Value   []byte
	Version int64
}
