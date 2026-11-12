// Package testbed creates and destroys the machines the end-to-end test loop runs on:
//
//  1. create machine(s)   2. add them with kvoadm   3. test   4. tear down
//
// It is a development tool, not a product feature: kvoadm itself never creates machines.
// Every machine is named and tagged with the run's ID, so a sweep can delete leftovers even when a
// test crashed before its teardown.
package testbed

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Prefix starts the name of every machine the testbed creates.
const Prefix = "kvt"

// RunID identifies one test run. It is part of every machine name.
type RunID string

var runIDPattern = regexp.MustCompile(`^[a-z0-9]{6,12}$`)

// NewRunID returns a random run ID, safe to use in machine names on every driver.
func NewRunID() RunID {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return RunID(hex.EncodeToString(b))
}

// Validate reports whether the run ID can be used in machine names.
func (r RunID) Validate() error {
	if !runIDPattern.MatchString(string(r)) {
		return fmt.Errorf("run id %q: want 6-12 lowercase letters or digits", r)
	}
	return nil
}

// Spec describes a machine to create.
type Spec struct {
	Role   string // short role, e.g. "cp", "w1"; part of the name
	CPUs   int
	Memory string // e.g. "4GiB"
	Disk   string // e.g. "20GiB"
	KVM    bool   // the machine must expose a usable /dev/kvm (nested virtualization)
	// Shared: on a network shared with the other Shared machines of the run, which reach it
	// directly. Without it, a machine only reaches the internet (and its own host).
	Shared bool
}

var rolePattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,7}$`)

// Validate reports whether the spec is usable.
func (s Spec) Validate() error {
	var errs []error
	if !rolePattern.MatchString(s.Role) {
		errs = append(errs, fmt.Errorf("role %q: want 1-8 lowercase letters or digits, starting with a letter", s.Role))
	}
	if s.CPUs < 1 {
		errs = append(errs, fmt.Errorf("cpus %d: want at least 1", s.CPUs))
	}
	if s.Memory == "" {
		errs = append(errs, errors.New("memory: required"))
	}
	if s.Disk == "" {
		errs = append(errs, errors.New("disk: required"))
	}
	return errors.Join(errs...)
}

// MachineName is the name a driver gives a machine: kvt-<run>-<role>.
func MachineName(run RunID, role string) string {
	return fmt.Sprintf("%s-%s-%s", Prefix, run, role)
}

// ParseMachineName returns the run ID and role of a testbed machine name, or ok=false for any other name.
func ParseMachineName(name string) (run RunID, role string, ok bool) {
	parts := strings.Split(name, "-")
	if len(parts) != 3 || parts[0] != Prefix {
		return "", "", false
	}
	run, role = RunID(parts[1]), parts[2]
	if run.Validate() != nil || !rolePattern.MatchString(role) {
		return "", "", false
	}
	return run, role, true
}

// Machine is a created machine.
type Machine struct {
	Name    string
	Run     RunID
	Role    string
	Created time.Time // zero when the driver doesn't know
}

// Driver creates machines somewhere: Lima VMs locally, the CI runner itself, a cloud later.
type Driver interface {
	// Create creates and starts a machine and waits until a command can run on it.
	Create(ctx context.Context, run RunID, spec Spec) (Machine, error)
	// Exec runs a command on the machine and returns its combined output.
	Exec(ctx context.Context, m Machine, cmd ...string) (string, error)
	// CopyTo copies a local file onto the machine.
	CopyTo(ctx context.Context, m Machine, local, remote string) error
	// Delete stops and deletes the machine. Deleting a machine that is gone is not an error.
	Delete(ctx context.Context, m Machine) error
	// List returns every testbed machine the driver can see, from any run.
	List(ctx context.Context) ([]Machine, error)
}

// SSHInfo is how to reach a machine over SSH (what kvoadm needs).
type SSHInfo struct {
	Host    string
	Port    int
	User    string // has passwordless sudo
	KeyFile string // private key that logs in as User
}

// SSHAccess is implemented by drivers whose machines kvoadm can set up over SSH.
type SSHAccess interface {
	SSH(ctx context.Context, m Machine) (SSHInfo, error)
}

// Leftovers picks the machines a sweep should delete: every testbed machine not belonging to keep,
// and, when olderThan > 0, only those created before now-olderThan (machines whose age is unknown are
// included, since a leftover's age often is).
func Leftovers(machines []Machine, keep RunID, now time.Time, olderThan time.Duration) []Machine {
	var out []Machine
	for _, m := range machines {
		if m.Run == keep {
			continue
		}
		if olderThan > 0 && !m.Created.IsZero() && now.Sub(m.Created) < olderThan {
			continue
		}
		out = append(out, m)
	}
	return out
}
