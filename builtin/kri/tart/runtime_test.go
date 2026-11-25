package tart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

// fakeMac is a Mac with Tart: VMs in memory, Apple's two-guest limit, files in a map.
type fakeMac struct {
	files    map[string][]byte
	vms      map[string]*fvm // by name; the image is one too (Source OCI)
	cmds     []string
	pulled   []string
	agentUp  bool // the guest agent answers once a VM runs
	noTart   bool
	execCode int
	failOn   string
}

type fvm struct {
	source  string
	running bool
	cpu     string
	mem     string
	disk    string
}

func newMac() *fakeMac {
	return &fakeMac{files: map[string][]byte{}, vms: map[string]*fvm{}, agentUp: true}
}

func (m *fakeMac) runningCount() int {
	n := 0
	for _, v := range m.vms {
		if v.running {
			n++
		}
	}
	return n
}

func (m *fakeMac) Run(_ context.Context, c Cmd) (int, error) {
	m.cmds = append(m.cmds, c.Name+" "+strings.Join(c.Args, " "))
	if c.Name == "sh" {
		return 0, nil
	}
	out := c.Stdout
	if out == nil {
		out = io.Discard
	}
	if m.noTart {
		return -1, errors.New("exec: tart: not found")
	}
	if m.failOn != "" && strings.Contains(strings.Join(c.Args, " "), m.failOn) {
		_, _ = io.WriteString(out, "boom")
		return 1, nil
	}
	a := c.Args
	switch a[0] {
	case "--version":
		_, _ = io.WriteString(out, "2.41.1\n")
	case "list":
		var names []string
		for n := range m.vms {
			names = append(names, n)
		}
		sort.Strings(names)
		var l []map[string]any
		for _, n := range names {
			v := m.vms[n]
			st := "stopped"
			if v.running {
				st = "running"
			}
			l = append(l, map[string]any{"Name": n, "Source": v.source, "Running": v.running, "State": st})
		}
		b, _ := json.Marshal(l)
		_, _ = out.Write(b)
	case "pull":
		m.pulled = append(m.pulled, a[1])
		m.vms[a[1]] = &fvm{source: "OCI"}
	case "clone":
		if _, ok := m.vms[a[1]]; !ok {
			_, _ = io.WriteString(out, "no such image")
			return 1, nil
		}
		m.vms[a[2]] = &fvm{source: "local"}
	case "set":
		v := m.vms[a[1]]
		for i := 2; i+1 < len(a); i += 2 {
			switch a[i] {
			case "--cpu":
				v.cpu = a[i+1]
			case "--memory":
				v.mem = a[i+1]
			case "--disk-size":
				v.disk = a[i+1]
			}
		}
	case "stop":
		if v, ok := m.vms[a[1]]; ok {
			v.running = false
		}
	case "delete":
		delete(m.vms, a[1])
	case "ip":
		_, _ = io.WriteString(out, "192.168.64.4\n")
	case "exec":
		i := 1
		for strings.HasPrefix(a[i], "-") {
			i++
		}
		v, ok := m.vms[a[i]]
		if !ok || !v.running || !m.agentUp {
			_, _ = io.WriteString(out, "guest agent not ready")
			return 1, nil
		}
		if c.Stdin != nil {
			_, _ = io.Copy(out, c.Stdin)
		}
		return m.execCode, nil
	default:
		return 1, errors.New("unknown tart command " + a[0])
	}
	return 0, nil
}

func (m *fakeMac) WriteFile(p string, d []byte, _ os.FileMode) error { m.files[p] = d; return nil }
func (m *fakeMac) ReadFile(p string) ([]byte, error) {
	if b, ok := m.files[p]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}
func (m *fakeMac) RemoveAll(p string) error { delete(m.files, p); return nil }
func (m *fakeMac) Glob(pattern string) ([]string, error) {
	var out []string
	prefix := strings.TrimSuffix(pattern, "kv-*.json")
	for p := range m.files {
		if strings.HasPrefix(p, prefix+"kv-") && strings.HasSuffix(p, ".json") {
			out = append(out, p)
		}
	}
	return out, nil
}

func rt(m *fakeMac) *Runtime {
	r := &Runtime{Host: m, StateDir: "/state", Sleep: func(d time.Duration) {}}
	r.Detach = func(c Cmd, _ string) error {
		// tart run NAME --no-graphics [--net-softnet]
		if m.runningCount() >= MaxRunning {
			return nil // Tart starts, then exits at once with the limit text; the VM isn't running
		}
		m.vms[c.Args[1]].running = true
		m.cmds = append(m.cmds, "DETACH "+c.Name+" "+strings.Join(c.Args, " "))
		return nil
	}
	return r
}

func silo(name string) kri.Spec {
	return kri.Spec{ID: kri.ID{Namespace: "ios", Name: name, UID: "abcdef123456"}, Image: "ghcr.io/cirruslabs/macos-tahoe-base:latest",
		CPU: 4, Memory: 8 << 30, DiskBytes: 100 << 30}
}

func TestLifecycle(t *testing.T) {
	m := newMac()
	r := rt(m)
	ctx := context.Background()
	s := silo("build")
	if st, _ := r.Status(ctx, s.ID); st.State != kri.Absent {
		t.Fatalf("before create: %v", st)
	}
	if err := r.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	if len(m.pulled) != 1 {
		t.Fatalf("pulled %v", m.pulled)
	}
	vmn := vmName(s.ID)
	if v := m.vms[vmn]; v == nil || v.cpu != "4" || v.mem != "8192" || v.disk != "100" {
		t.Fatalf("vm %+v", v)
	}
	if err := r.Create(ctx, s); err != nil { // idempotent
		t.Fatal(err)
	}
	if len(m.pulled) != 1 {
		t.Fatalf("pulled again: %v", m.pulled)
	}
	if st, _ := r.Status(ctx, s.ID); st.State != kri.Created {
		t.Fatalf("after create: %v", st)
	}
	if err := r.Start(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	st, _ := r.Status(ctx, s.ID)
	if st.State != kri.Running || st.Address != "" { // the VM's NAT address is not a cluster address
		t.Fatalf("running: %+v", st)
	}
	var out bytes.Buffer
	code, err := r.Exec(ctx, s.ID, kri.ExecRequest{Command: []string{"cat"}, Stdin: strings.NewReader("hi"), Stdout: &out})
	if err != nil || code != 0 || out.String() != "hi" {
		t.Fatalf("exec %d %v %q", code, err, out.String())
	}
	ids, _ := r.List(ctx)
	if len(ids) != 1 || ids[0] != s.ID {
		t.Fatalf("list %v", ids)
	}
	if err := r.Stop(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.Status(ctx, s.ID); st.State != kri.Stopped {
		t.Fatalf("after stop: %+v", st)
	}
	if err := r.Delete(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.vms[vmn]; ok {
		t.Fatal("vm kept")
	}
	if st, _ := r.Status(ctx, s.ID); st.State != kri.Absent {
		t.Fatalf("after delete: %+v", st)
	}
	if err := r.Delete(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
}

func TestTwoRunningAtMost(t *testing.T) {
	m := newMac()
	r := rt(m)
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c"} {
		if err := r.Create(ctx, silo(n)); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"a", "b"} {
		if err := r.Start(ctx, silo(n).ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Start(ctx, silo("c").ID); !errors.Is(err, ErrCapacity) {
		t.Fatalf("third start: %v", err)
	}
	for _, c := range m.cmds {
		if strings.HasPrefix(c, "DETACH") && strings.Contains(c, vmName(silo("c").ID)) {
			t.Fatalf("tart run was asked for the third: %v", m.cmds)
		}
	}
	// A stopped silo doesn't count.
	if err := r.Stop(ctx, silo("a").ID); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo("c").ID); err != nil {
		t.Fatalf("after a stop: %v", err)
	}
	// Starting one that runs is a no-op even at the limit.
	if err := r.Start(ctx, silo("b").ID); err != nil {
		t.Fatalf("restart a running one: %v", err)
	}
}

func TestStartSaysCapacityWhenTartRefuses(t *testing.T) {
	// Something else on the Mac holds two guests Kevaso doesn't count: tart run exits at once with
	// Apple's limit text, and the VM is not running.
	m := newMac()
	r := rt(m)
	ctx := context.Background()
	s := silo("a")
	if err := r.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	m.agentUp = false
	m.files["/state/"+vmName(s.ID)+".log"] = []byte("Error: The number of VMs exceeds the system limit (other running VMs: x, y)")
	r.Detach = func(Cmd, string) error { return nil } // tart run started and died
	if err := r.Start(ctx, s.ID); !errors.Is(err, ErrCapacity) {
		t.Fatalf("%v", err)
	}
}

func TestSoftnetFlag(t *testing.T) {
	m := newMac()
	r := rt(m)
	r.Softnet = true
	ctx := context.Background()
	if err := r.Create(ctx, silo("a")); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo("a").ID); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range m.cmds {
		found = found || (strings.HasPrefix(c, "DETACH") && strings.Contains(c, "--net-softnet") && strings.Contains(c, "--no-graphics"))
	}
	if !found {
		t.Fatalf("no softnet run: %v", m.cmds)
	}
}

func TestResetKeepsIDAndGivesFreshClone(t *testing.T) {
	m := newMac()
	r := rt(m)
	ctx := context.Background()
	s := silo("a")
	if err := r.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	m.vms[vmName(s.ID)].cpu = "marked"
	if err := r.Reset(ctx, s); err != nil {
		t.Fatal(err)
	}
	if m.vms[vmName(s.ID)].cpu != "4" {
		t.Fatalf("not a fresh clone: %+v", m.vms[vmName(s.ID)])
	}
	if st, _ := r.Status(ctx, s.ID); st.State != kri.Created {
		t.Fatalf("after reset: %+v", st)
	}
}

func TestStatusWhenVMVanished(t *testing.T) {
	m := newMac()
	r := rt(m)
	ctx := context.Background()
	s := silo("a")
	_ = r.Create(ctx, s)
	delete(m.vms, vmName(s.ID))
	if st, _ := r.Status(ctx, s.ID); st.State != kri.Failed {
		t.Fatalf("%+v", st)
	}
	if err := r.Start(ctx, s.ID); !errors.Is(err, kri.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestExecOnAbsentSilo(t *testing.T) {
	r := rt(newMac())
	if _, err := r.Exec(context.Background(), silo("x").ID, kri.ExecRequest{Command: []string{"true"}}); !errors.Is(err, kri.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestInstall(t *testing.T) {
	m := newMac()
	r := rt(m)
	var said []string
	if err := r.Install(context.Background(), func(s string) { said = append(said, s) }); err != nil {
		t.Fatal(err)
	}
	if r.Info().Version != "2.41.1" || len(said) != 1 || !strings.Contains(said[0], "FSL-1.1-ALv2") || !strings.Contains(said[0], "two") && !strings.Contains(said[0], "2") {
		t.Fatalf("%v %v", r.Info(), said)
	}
	m.noTart = true
	if err := r.Install(context.Background(), nil); !errors.Is(err, ErrNoTart) {
		t.Fatalf("%v", err)
	}
}

func TestVMNameIsSafeAndCarriesUID(t *testing.T) {
	a := vmName(kri.ID{Namespace: "a b", Name: "x/y", UID: "1234567890"})
	if strings.ContainsAny(a, " /") || !strings.HasSuffix(a, "-12345678") {
		t.Fatal(a)
	}
	if vmName(kri.ID{Namespace: "n", Name: "s", UID: "u1"}) == vmName(kri.ID{Namespace: "n", Name: "s", UID: "u2"}) {
		t.Fatal("a re-created silo must be another VM")
	}
}

func TestImplementsOptionalInterfaces(t *testing.T) {
	var r kri.Runtime = &Runtime{}
	if _, ok := r.(kri.Resetter); !ok {
		t.Fatal("Resetter")
	}
	if _, ok := r.(kri.Killer); !ok {
		t.Fatal("Killer")
	}
	if _, ok := r.(kri.HostStorage); !ok {
		t.Fatal("HostStorage")
	}
}

func TestRunAsWrapsEveryTartCommandInSudo(t *testing.T) {
	m := newMac()
	r := rt(m)
	r.RunAs, r.TartHome = "dev", "/Users/dev/.tart"
	c := r.cmd("list", "--format", "json").Cmd
	if c.Name != "sudo" || strings.Join(c.Args, " ") != "-n -H -u dev env PATH="+hostexec.DefaultPath()+" TART_HOME=/Users/dev/.tart tart list --format json" {
		t.Fatalf("%s %v", c.Name, c.Args)
	}
	if c.Dir != "/" { // the user can't read kevasod's own command folder (a bash tart warns into JSON)
		t.Fatalf("sudo -u starts in %q, not /", c.Dir)
	}
	r.RunAs = ""
	if c := r.cmd("list").Cmd; c.Name != "tart" || len(c.Env) != 1 {
		t.Fatalf("%+v", c)
	}
}

func TestStartWaitsForTartToListTheVMAsRunning(t *testing.T) {
	// A real Mac lists a VM as running a moment after `tart run`: the first polls say it isn't.
	m := newMac()
	r := rt(m)
	ctx := context.Background()
	s := silo("a")
	if err := r.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	polls := 0
	r.Detach = func(Cmd, string) error { return nil } // the process started, the VM isn't up yet
	r.Sleep = func(time.Duration) {
		if polls++; polls == 3 {
			m.vms[vmName(s.ID)].running = true
		}
	}
	if err := r.Start(ctx, s.ID); err != nil {
		t.Fatalf("a slow start failed: %v", err)
	}
	if polls < 3 {
		t.Fatalf("it didn't wait: %d polls", polls)
	}
}
