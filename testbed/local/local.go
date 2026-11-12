// Package local is the testbed driver that uses the current machine as the only machine. CI uses it on
// GitHub's ubuntu-latest runner, which exposes KVM (research E036), so the runner itself is the host
// under test.
package local

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"kevaso.com/core/testbed"
)

// Driver runs everything on this machine.
type Driver struct{}

// Create implements testbed.Driver: the machine already exists; it only gets a testbed name.
func (Driver) Create(_ context.Context, run testbed.RunID, spec testbed.Spec) (testbed.Machine, error) {
	if err := run.Validate(); err != nil {
		return testbed.Machine{}, err
	}
	if err := spec.Validate(); err != nil {
		return testbed.Machine{}, err
	}
	return testbed.Machine{Name: testbed.MachineName(run, spec.Role), Run: run, Role: spec.Role}, nil
}

// Exec implements testbed.Driver.
func (Driver) Exec(ctx context.Context, _ testbed.Machine, cmd ...string) (string, error) {
	if len(cmd) == 0 {
		return "", fmt.Errorf("exec: no command")
	}
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	return string(out), err
}

// CopyTo implements testbed.Driver.
func (Driver) CopyTo(_ context.Context, _ testbed.Machine, local, remote string) error {
	in, err := os.Open(local)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(remote, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Delete implements testbed.Driver: nothing to delete.
func (Driver) Delete(context.Context, testbed.Machine) error { return nil }

// List implements testbed.Driver: there are never leftovers.
func (Driver) List(context.Context) ([]testbed.Machine, error) { return nil, nil }

var _ testbed.Driver = Driver{}
