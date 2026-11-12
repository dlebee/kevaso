package lima

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"kevaso.com/core/testbed"
)

// fakeRunner records limactl calls and answers "list" from a fixed set of instance names.
type fakeRunner struct {
	calls     [][]string
	instances []string
	failOn    string // first argument that should fail
	sawConfig string // content of the config file passed to "start"
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	if len(args) > 0 && args[0] == f.failOn {
		return nil, errors.New("boom")
	}
	switch args[0] {
	case "list":
		var b strings.Builder
		for _, n := range f.instances {
			b.WriteString(`{"name":"` + n + `","status":"Running"}` + "\n")
		}
		return []byte(b.String()), nil
	case "start":
		data, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return nil, err
		}
		f.sawConfig = string(data)
	case "shell":
		return []byte("ok\n"), nil
	}
	return nil, nil
}

var spec = testbed.Spec{Role: "w1", CPUs: 4, Memory: "8GiB", Disk: "30GiB", KVM: true}

func TestConfigWithKVM(t *testing.T) {
	cfg, err := Config(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"vmType: vz", "nestedVirtualization: true", "cpus: 4", "memory: 8GiB", "disk: 30GiB",
		"mounts: []", `usermod -aG kvm "{{.User}}"`, "chmod 0666 /dev/kvm",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config is missing %q:\n%s", want, cfg)
		}
	}
}

func TestConfigWithoutKVM(t *testing.T) {
	s := spec
	s.KVM = false
	cfg, err := Config(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "nestedVirtualization: false") || strings.Contains(cfg, "provision:") {
		t.Fatalf("config without KVM should disable nesting and skip the kvm provision:\n%s", cfg)
	}
}

func TestConfigRejectsBadSpec(t *testing.T) {
	if _, err := Config(testbed.Spec{}); err == nil {
		t.Fatal("Config(empty spec) = nil error")
	}
}

func TestCreateStartsNamedVMAndCleansConfig(t *testing.T) {
	r := &fakeRunner{}
	d := &Driver{Runner: r, TmpDir: t.TempDir()}
	m, err := d.Create(context.Background(), "a1b2c3d4", spec)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "kvt-a1b2c3d4-w1" || m.Run != "a1b2c3d4" || m.Role != "w1" {
		t.Fatalf("machine = %+v", m)
	}
	got := strings.Join(r.calls[0][:3], " ")
	if got != "start --name=kvt-a1b2c3d4-w1 --tty=false" {
		t.Fatalf("start args = %q", got)
	}
	if !strings.Contains(r.sawConfig, "nestedVirtualization: true") {
		t.Fatalf("limactl got the wrong config:\n%s", r.sawConfig)
	}
	left, _ := os.ReadDir(d.TmpDir)
	if len(left) != 0 {
		t.Fatalf("config file left behind: %v", left)
	}
}

func TestCreateRejectsBadRunID(t *testing.T) {
	r := &fakeRunner{}
	d := &Driver{Runner: r, TmpDir: t.TempDir()}
	if _, err := d.Create(context.Background(), "BAD", spec); err == nil {
		t.Fatal("Create with a bad run id succeeded")
	}
	if len(r.calls) != 0 {
		t.Fatalf("limactl was called: %v", r.calls)
	}
}

func TestCreateReportsStartFailure(t *testing.T) {
	d := &Driver{Runner: &fakeRunner{failOn: "start"}, TmpDir: t.TempDir()}
	if _, err := d.Create(context.Background(), "a1b2c3d4", spec); err == nil {
		t.Fatal("Create ignored a failing limactl start")
	}
}

func TestListOnlyReturnsTestbedMachines(t *testing.T) {
	r := &fakeRunner{instances: []string{"kvt-a1b2c3d4-cp", "kvaso-e008", "default", "kvt-zz99yy88-w1"}}
	ms, err := (&Driver{Runner: r}).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].Name != "kvt-a1b2c3d4-cp" || ms[1].Run != "zz99yy88" {
		t.Fatalf("List = %+v", ms)
	}
}

func TestDeleteRefusesForeignNames(t *testing.T) {
	r := &fakeRunner{instances: []string{"kvaso-e008"}}
	err := (&Driver{Runner: r}).Delete(context.Background(), testbed.Machine{Name: "kvaso-e008"})
	if err == nil {
		t.Fatal("Delete accepted a VM that isn't a testbed machine")
	}
	for _, c := range r.calls {
		if c[0] == "delete" {
			t.Fatalf("limactl delete was called: %v", c)
		}
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	r := &fakeRunner{}
	if err := (&Driver{Runner: r}).Delete(context.Background(), testbed.Machine{Name: "kvt-a1b2c3d4-cp"}); err != nil {
		t.Fatalf("Delete of a missing machine: %v", err)
	}
	r = &fakeRunner{instances: []string{"kvt-a1b2c3d4-cp"}}
	if err := (&Driver{Runner: r}).Delete(context.Background(), testbed.Machine{Name: "kvt-a1b2c3d4-cp"}); err != nil {
		t.Fatal(err)
	}
	last := r.calls[len(r.calls)-1]
	if strings.Join(last, " ") != "delete --force kvt-a1b2c3d4-cp" {
		t.Fatalf("last call = %v", last)
	}
}

func TestExecAndCopyArgs(t *testing.T) {
	r := &fakeRunner{}
	d := &Driver{Runner: r}
	m := testbed.Machine{Name: "kvt-a1b2c3d4-cp"}
	if out, err := d.Exec(context.Background(), m, "uname", "-a"); err != nil || out != "ok\n" {
		t.Fatalf("Exec = %q, %v", out, err)
	}
	if err := d.CopyTo(context.Background(), m, "/tmp/x", "/tmp/y"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls[0], " "); got != "shell kvt-a1b2c3d4-cp -- uname -a" {
		t.Fatalf("exec args = %q", got)
	}
	if got := strings.Join(r.calls[1], " "); got != "copy /tmp/x kvt-a1b2c3d4-cp:/tmp/y" {
		t.Fatalf("copy args = %q", got)
	}
}
