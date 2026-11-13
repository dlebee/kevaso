package container

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

// fake is a host with a container engine that keeps containers in memory.
type fake struct {
	fmu        sync.Mutex // files: Exec looks for its command from another goroutine
	files      map[string][]byte
	cmds       []string
	containers map[string]string // name → status
	images     map[string]bool
	pid        int
	wired      map[int]bool
	execHook   func(context.Context, hostexec.Cmd) (int, error) // docker exec, if set
}

func newFake() *fake {
	return &fake{files: map[string][]byte{}, containers: map[string]string{}, images: map[string]bool{}, pid: 100, wired: map[int]bool{}}
}

func (f *fake) Run(ctx context.Context, c hostexec.Cmd) (int, error) {
	f.cmds = append(f.cmds, c.Name+" "+strings.Join(c.Args, " "))
	a := c.Args
	out := func(s string) {
		if c.Stdout != nil {
			_, _ = io.WriteString(c.Stdout, s)
		}
	}
	fail := func(s string) (int, error) {
		if c.Stderr != nil {
			_, _ = io.WriteString(c.Stderr, s)
		}
		return 1, nil
	}
	switch {
	case c.Name == "nsenter" && strings.Contains(strings.Join(a, " "), "addr show dev eth0"):
		if !f.wired[f.pid] {
			return fail("")
		}
		out("2: eth0 inet 10.64.0.2/24 scope global eth0")
	case c.Name == "nsenter" && strings.Contains(strings.Join(a, " "), "route add default"):
		f.wired[f.pid] = true
	case c.Name == "docker":
		switch a[0] {
		case "container":
			if a[1] != "inspect" {
				break
			}
			st, ok := f.containers[a[len(a)-1]]
			if !ok {
				return fail("Error: No such object")
			}
			out(fmt.Sprintf("%s %d", st, f.pid))
		case "image":
			if !f.images[a[len(a)-1]] {
				return fail("No such image")
			}
		case "import":
			if c.Stdin != nil {
				_, _ = io.ReadAll(c.Stdin)
			}
			f.images[a[len(a)-1]] = true
		case "run":
			name := a[indexOf(a, "--name")+1]
			if a[1] == "--rm" {
				return 0, nil
			}
			f.containers[name] = "running"
		case "start":
			f.containers[a[1]] = "running"
		case "stop":
			f.containers[a[len(a)-1]] = "exited"
		case "rm":
			delete(f.containers, a[len(a)-1])
		case "exec":
			if f.execHook != nil {
				return f.execHook(ctx, c)
			}
			return 5, nil
		case "volume":
			if a[1] == "inspect" {
				return fail("no such volume")
			}
		}
	}
	return 0, nil
}

func indexOf(l []string, v string) int {
	for i, x := range l {
		if x == v {
			return i
		}
	}
	return -1
}

func (f *fake) WriteFile(p string, d []byte, _ os.FileMode) error {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	f.files[p] = d
	return nil
}
func (f *fake) ReadFile(p string) ([]byte, error) {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	if b, ok := f.files[p]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}
func (f *fake) RemoveAll(p string) error {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	for k := range f.files {
		if k == p || strings.HasPrefix(k, p+"/") {
			delete(f.files, k)
		}
	}
	return nil
}
func (f *fake) Glob(pattern string) ([]string, error) {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	var out []string
	for k := range f.files {
		if ok, _ := filepath.Match(pattern, k); ok {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fake) last(prefix string) string {
	for i := len(f.cmds) - 1; i >= 0; i-- {
		if strings.HasPrefix(f.cmds[i], prefix) {
			return f.cmds[i]
		}
	}
	return ""
}

func runtime(t *testing.T, f *fake) *Runtime {
	self := filepath.Join(t.TempDir(), "kevasod")
	_ = os.WriteFile(self, []byte("binary"), 0o755)
	return &Runtime{Host: f, Engine: "docker", Self: self, CABundle: []byte("CAS")}
}

var silo = kri.ID{Namespace: "shop", Name: "api", UID: "u1"}

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	// A VM already holds .2: the container gets .3 (one pool for the bridge).
	f.files[cloudhypervisor.SilosDir+"/abc/silo.json"] = []byte(`{"ip":"10.64.0.2"}`)
	spec := kri.Spec{ID: silo, Image: "ubuntu-24.04", CPU: 2, Memory: 512 << 20, Volumes: []kri.Volume{{Name: "data", MountPath: "/data"}}}
	if err := r.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	s, _ := r.load(silo)
	if s.IP != "10.64.0.3" {
		t.Fatalf("address %s, want 10.64.0.3 (after the VM's)", s.IP)
	}
	n := NamesFor(silo)
	for _, want := range []string{
		"docker pull --quiet docker.io/library/ubuntu:24.04",
		"docker volume create --label kevaso.com/uid=u1 " + VolumeName(silo, "data"),
		"docker import --change ENTRYPOINT [\"/kevaso-pause\"] - localhost/kevaso-pause:",
		"docker run -d --name " + n.Pause + " --hostname api --network none --read-only --cap-drop ALL",
		"ip link add " + n.Veth + " type veth peer name " + n.Peer,
		"nsenter -t 100 -n ip addr add 10.64.0.3/24 dev eth0",
		"nsenter -t 100 -n ip route add default via 10.64.0.1",
		"ip link set " + n.Veth + " master kvbr0 up",
	} {
		found := false
		for _, c := range f.cmds {
			if strings.HasPrefix(c, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %q in:\n%s", want, strings.Join(f.cmds, "\n"))
		}
	}
	if !strings.Contains(string(f.files[n.Dir+"/resolv.conf"]), "nameserver 10.64.0.1\nsearch shop.kevaso kevaso") {
		t.Errorf("resolv.conf %q", f.files[n.Dir+"/resolv.conf"])
	}
	if st, _ := r.Status(ctx, silo); st.State != kri.Created {
		t.Fatalf("after create: %v", st.State)
	}

	// Init containers: the silo's image, its network and volumes, removed after.
	code, err := r.RunInit(ctx, silo, kri.InitStep{Name: "migrate", Shell: "bash", Run: "echo hi > /data/x"}, io.Discard)
	init := f.last("docker run --rm")
	if err != nil || code != 0 || !strings.Contains(init, "--network container:"+n.Pause) || !strings.Contains(init, VolumeName(silo, "data")+":/data") ||
		!strings.HasSuffix(init, "--entrypoint bash docker.io/library/ubuntu:24.04 -c echo hi > /data/x") {
		t.Fatalf("init container: %d %v\n%s", code, err, init)
	}

	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	main := f.last("docker run -d --name " + n.Main)
	for _, want := range []string{"--network container:" + n.Pause, "--security-opt no-new-privileges", "-v " + n.Dir + "/broker:/run/kevaso",
		"SSL_CERT_FILE=/etc/ssl/certs/kevaso-ca-bundle.crt", "--cpus 2", "--memory 536870912",
		"-v " + n.Dir + "/resolv.conf:/etc/resolv.conf:ro", "docker.io/library/ubuntu:24.04 sleep infinity"} {
		if !strings.Contains(main, want) {
			t.Errorf("main container %q missing %q", main, want)
		}
	}
	if strings.Contains(main, "kvo-guest") || strings.Contains(main, r.Self) {
		t.Errorf("something of Kevaso's in a user's container: %s", main)
	}
	if strings.Contains(main, "--hostname") || strings.Contains(main, "--uts") {
		t.Error("--hostname or --uts with a container network: Docker refuses both")
	}
	if st, _ := r.Status(ctx, silo); st.State != kri.Running || st.Address != "10.64.0.3" {
		t.Fatalf("running: %+v", st)
	}
	if code, _ := r.Exec(ctx, silo, kri.ExecRequest{Command: []string{"false"}}); code != 5 || !strings.HasSuffix(f.last("docker exec"), " "+n.Main+" false") {
		t.Fatalf("exec: %d %s", code, f.last("docker exec"))
	}
	// A host reboot: the pause container is gone with its namespace; Start brings both back, rewired.
	_ = r.Stop(ctx, silo)
	f.containers[n.Pause] = "exited"
	f.pid = 200
	if st, _ := r.Status(ctx, silo); st.State != kri.Stopped {
		t.Fatalf("after stop: %v", st.State)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.cmds, "\n"), "nsenter -t 200 -n ip addr add 10.64.0.3/24 dev eth0") || f.containers[n.Main] != "running" {
		t.Fatal("not rewired after the pause container restarted")
	}
	if err := r.Delete(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if len(f.containers) != 0 || f.last("docker volume rm") == "" || f.last("ip link del "+n.Veth) == "" {
		t.Fatalf("delete left %v", f.containers)
	}
	if st, _ := r.Status(ctx, silo); st.State != kri.Absent {
		t.Fatal("state kept")
	}
}

func TestMainCommandAndImages(t *testing.T) {
	if got := MainCommand("ubuntu-24.04", nil); strings.Join(got, " ") != "sleep infinity" {
		t.Errorf("ubuntu default: %v", got)
	}
	if got := MainCommand("shop-api:v12", nil); got != nil {
		t.Errorf("an app image keeps its own command: %v", got)
	}
	if got := MainCommand("ubuntu-24.04", []string{"python3", "-m", "http.server"}); got[0] != "python3" {
		t.Errorf("explicit command: %v", got)
	}
	if ImageRef("ghcr.io/x/y:1") != "ghcr.io/x/y:1" || ImageRef("ubuntu-24.04") != "docker.io/library/ubuntu:24.04" {
		t.Error("image refs")
	}
	if NamesFor(silo).Veth != cloudhypervisor.NamesFor(silo).Tap {
		t.Error("the veth must be named like a VM's tap: the firewall's anti-spoofing rules use it")
	}
}

// Kevaso's own silos run from images of their own, built from kevasod on the host: never pulled,
// nothing mounted into them beyond what any silo gets.
func TestKevasoImages(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	id := kri.ID{Namespace: "kevaso-system", Name: "ingress", UID: "u9"}
	if err := r.Create(ctx, kri.Spec{ID: id, Image: "kevaso-ingress"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, id); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(f.cmds, "\n")
	if strings.Contains(all, "pull") && strings.Contains(all, "kevaso-ingress") {
		t.Fatalf("pulled Kevaso's own image:\n%s", all)
	}
	imp := f.last("docker import --change ENTRYPOINT [\"/usr/local/bin/kvo-guest\",\"ingress\"]")
	if !strings.Contains(imp, "localhost/kevaso-ingress:") {
		t.Fatalf("ingress image not built: %s", imp)
	}
	main := f.last("docker run -d --name " + NamesFor(id).Main)
	if !strings.HasSuffix(main, strings.Fields(imp)[len(strings.Fields(imp))-1]) || strings.Contains(main, "kvo-guest:ro") {
		t.Fatalf("main container: %s", main)
	}
}
