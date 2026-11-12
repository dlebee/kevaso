// Package lima is the testbed driver for local development: Lima VMs on a Mac (vz with nested
// virtualization, so microVMs run inside them) or on Linux.
//
// Proven in research E003 (KVM inside Lima on an M3 Mac) and E004 / E008 (OpenShell and Cloud
// Hypervisor run inside such a VM).
package lima

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"kevaso.com/core/testbed"
)

// Runner runs limactl. The real one shells out; tests use a fake.
type Runner interface {
	Run(ctx context.Context, args ...string) (stdout []byte, err error)
}

// ExecRunner runs the limactl binary.
type ExecRunner struct{ Bin string }

// Run implements Runner.
func (r ExecRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	bin := r.Bin
	if bin == "" {
		bin = "limactl"
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("limactl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Driver creates Lima VMs.
type Driver struct {
	Runner Runner
	TmpDir string // where VM configs are written; os.TempDir() when empty
}

// New returns a driver that shells out to limactl.
func New() *Driver { return &Driver{Runner: ExecRunner{}} }

var configTemplate = template.Must(template.New("lima").Parse(`# Written by the Kevaso testbed. Throwaway VM for tests.
minimumLimaVersion: 2.0.0
base:
- template:_images/ubuntu-24.04
vmType: vz
nestedVirtualization: {{.KVM}}
cpus: {{.CPUs}}
memory: {{.Memory}}
disk: {{.Disk}}
mounts: []
{{- if .KVM}}
# Let the default user open /dev/kvm (Lima's SSH session keeps its old groups, so a group change
# alone isn't enough). Throwaway test VM only.
provision:
- mode: system
  script: |
    #!/bin/sh
    set -eu
    usermod -aG kvm "{{"{{"}}.User{{"}}"}}"
    echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666"' > /etc/udev/rules.d/99-kvm-dev.rules
    chmod 0666 /dev/kvm
{{- end}}
`))

// Config renders the Lima YAML for a spec.
func Config(spec testbed.Spec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	if err := configTemplate.Execute(&b, spec); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Create implements testbed.Driver.
func (d *Driver) Create(ctx context.Context, run testbed.RunID, spec testbed.Spec) (testbed.Machine, error) {
	if err := run.Validate(); err != nil {
		return testbed.Machine{}, err
	}
	cfg, err := Config(spec)
	if err != nil {
		return testbed.Machine{}, err
	}
	name := testbed.MachineName(run, spec.Role)
	dir := d.TmpDir
	if dir == "" {
		dir = os.TempDir()
	}
	path := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		return testbed.Machine{}, err
	}
	defer os.Remove(path)
	if _, err := d.Runner.Run(ctx, "start", "--name="+name, "--tty=false", path); err != nil {
		return testbed.Machine{}, err
	}
	return testbed.Machine{Name: name, Run: run, Role: spec.Role}, nil
}

// Exec implements testbed.Driver.
func (d *Driver) Exec(ctx context.Context, m testbed.Machine, cmd ...string) (string, error) {
	out, err := d.Runner.Run(ctx, append([]string{"shell", m.Name, "--"}, cmd...)...)
	return string(out), err
}

// CopyTo implements testbed.Driver.
func (d *Driver) CopyTo(ctx context.Context, m testbed.Machine, local, remote string) error {
	_, err := d.Runner.Run(ctx, "copy", local, m.Name+":"+remote)
	return err
}

// Delete implements testbed.Driver. Lima refuses to delete a VM that doesn't exist, so Delete checks first.
func (d *Driver) Delete(ctx context.Context, m testbed.Machine) error {
	if _, _, ok := testbed.ParseMachineName(m.Name); !ok {
		return fmt.Errorf("refusing to delete %q: not a testbed machine", m.Name)
	}
	all, err := d.List(ctx)
	if err != nil {
		return err
	}
	for _, x := range all {
		if x.Name == m.Name {
			_, err := d.Runner.Run(ctx, "delete", "--force", m.Name)
			return err
		}
	}
	return nil
}

// List implements testbed.Driver. Only machines whose name parses as a testbed name are returned, so
// a sweep can never touch someone else's VM.
func (d *Driver) List(ctx context.Context) ([]testbed.Machine, error) {
	out, err := d.Runner.Run(ctx, "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	return parseList(out)
}

// limactl list --format json prints one JSON object per line.
func parseList(out []byte) ([]testbed.Machine, error) {
	var ms []testbed.Machine
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var inst struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(line, &inst); err != nil {
			return nil, fmt.Errorf("parse limactl list: %w", err)
		}
		run, role, ok := testbed.ParseMachineName(inst.Name)
		if !ok {
			continue
		}
		ms = append(ms, testbed.Machine{Name: inst.Name, Run: run, Role: role})
	}
	return ms, sc.Err()
}

var _ testbed.Driver = (*Driver)(nil)
