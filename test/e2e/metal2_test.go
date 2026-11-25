//go:build metal

package e2e

// The two-machine metal suite (TestMetal2…): machine 1 (KEVASO_METAL_*) as the system node only,
// machine 2 (KEVASO_METAL2_*) as a worker joined over the external IPs, the mesh between them;
// some tests also make machine 1 a worker. A different cluster from the one-machine suite's, so
// the two suites run in separate go test runs (-run '^TestMetal2' or the rest); each refuses to
// start in a run where the other made its cluster. Both machines are reset at the start and at
// the end (TestMain).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed/remote"
)

const metalHost2 = "metal-2"

// metalPair is the two machines' cluster.
type metalPair struct {
	m1, m2   *metalSuite
	m1Worker bool // machine 1 runs silos too (ensureTwoWorkers)
	bin      string
	// recoveryKey is what kvoadm init printed for the cluster (in memory only, never logged):
	// TestMetal2RestoreKeepsWhatItDoesntKnow restores with it. Empty on a reused cluster.
	recoveryKey string
	// apiPort is the port the Mac and the tests dial for machine 1's API. A pair lab sets
	// KEVASO_METAL_API_PORT to its slot port; a real pair leaves it unset and listens on 6443.
	apiPort string
	mu      sync.Mutex
}

var pairState struct {
	once    sync.Once
	p       *metalPair
	err     error
	skip    string
	touched []*remote.Driver // reached: reset at the end
}

// pair is the suite for one test: c1 and c2 run commands on machine 1 and 2 (kvo goes to the one
// cluster either way).
type pair struct {
	*metalPair
	c1, c2 *mt
	t      *testing.T
}

func metal2(t *testing.T) *pair {
	t.Helper()
	if metalState.s != nil {
		t.Fatal("this run made the one-machine cluster: run the two-machine tests on their own (-run '^TestMetal2')")
	}
	pairState.once.Do(func() { pairState.p, pairState.skip, pairState.err = setUpPair() })
	if pairState.skip != "" {
		t.Skip(pairState.skip)
	}
	if pairState.err != nil {
		t.Fatalf("the two-machine cluster: %v", pairState.err)
	}
	p := pairState.p
	ctx := context.Background()
	return &pair{metalPair: p, t: t, c1: &mt{metalSuite: p.m1, t: t, ctx: ctx}, c2: &mt{metalSuite: p.m2, t: t, ctx: ctx}}
}

// reach connects to a machine and reads what the suite needs of it.
func reach(ctx context.Context, cfg remote.Config) (*metalSuite, error) {
	s := &metalSuite{cfg: cfg, d: remote.New(cfg)}
	out, err := s.d.Run(ctx, `uname -m; test -c /dev/kvm && echo kvm`, nil)
	if err != nil {
		return nil, fmt.Errorf("reaching %s: %w", cfg.SSHTarget(), err)
	}
	pairState.touched = append(pairState.touched, s.d)
	f := strings.Fields(out)
	if len(f) == 0 {
		return nil, fmt.Errorf("%s said %q", cfg.SSHTarget(), out)
	}
	s.uname = f[0]
	s.arch = map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[s.uname]
	if s.arch == "" || !strings.Contains(out, "kvm") {
		return nil, fmt.Errorf("%s: %s, kvm %v: want x86_64 or aarch64 with KVM", cfg.SSHTarget(), s.uname, strings.Contains(out, "kvm"))
	}
	if who, err := s.d.RunAsLogin(ctx, `echo "${SSH_CLIENT%% *}"`); err == nil {
		s.macIP = strings.TrimSpace(who)
	}
	if _, err := s.d.RecordBaseline(ctx); err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.SSHTarget(), err)
	}
	if err := s.d.Reset(ctx); err != nil {
		return nil, fmt.Errorf("%s, the starting reset: %w", cfg.SSHTarget(), err)
	}
	// hostPort DNAT matches the external address, so that address has to be on an
	// interface. The reset removes kv* links and :kv addresses; a netplan address stays.
	// The internal address is not checked here: a real pair may omit it.
	addr, err := s.d.Run(ctx, "ip -4 -o addr", nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.SSHTarget(), err)
	}
	if !strings.Contains(addr+" ", cfg.ExternalIP+"/") {
		return nil, fmt.Errorf("%s isn't on any interface of %s (ip -4 addr): [external] ports match that address", cfg.ExternalIP, cfg.SSHTarget())
	}
	return s, nil
}

func setUpPair() (p *metalPair, skip string, err error) {
	cfg1, err1 := remote.FromEnv(os.Getenv)
	cfg2, err2 := remote.FromEnvPrefix(os.Getenv, remote.SecondPrefix)
	for _, e := range []error{err1, err2} {
		if errors.Is(e, remote.ErrNotConfigured) {
			return nil, e.Error() + " (the two-machine tests need both machines)", nil
		}
		if e != nil {
			return nil, "", e
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	pinGoEnv()
	say := func(f string, a ...any) { fmt.Printf("metal2: "+f+"\n", a...) }
	apiPort, err := metalAPIPort()
	if err != nil {
		return nil, "", err
	}
	if err := metalDialPorts(); err != nil {
		return nil, "", err
	}
	p = &metalPair{apiPort: apiPort}
	reuse := os.Getenv("KEVASO_METAL_REUSE") != ""
	if reuse { // the cluster kept from an earlier run, if it answers (no reset, no init)
		base, err := os.UserHomeDir()
		if err != nil {
			return nil, "", err
		}
		home := filepath.Join(base, ".kevaso-metal", "pair-"+cfg1.ExternalIP)
		for k, v := range map[string]string{"HOME": home, "KVO_CONFIG": metalAdminKvo(home, "metal2"), "KVO_TOKEN_STORE": "file", "KVO_SERVER": ""} {
			_ = os.Setenv(k, v)
		}
		if out, code := kvoOut(ctx, "get", "host", metalHost2, "-o", "json"); code == 0 {
			p.m1, p.m2 = &metalSuite{cfg: cfg1, d: remote.New(cfg1), arch: "amd64", uname: "x86_64", suffix: "kevaso"},
				&metalSuite{cfg: cfg2, d: remote.New(cfg2), arch: "amd64", uname: "x86_64", suffix: "kevaso"}
			pairState.touched = append(pairState.touched, p.m1.d, p.m2.d)
			var h v1.Host
			if json.Unmarshal([]byte(out), &h) == nil && h.Spec.Components.Worker != nil {
				var h1 v1.Host
				if o1, c1 := kvoOut(ctx, "get", "host", metalHost, "-o", "json"); c1 == 0 && json.Unmarshal([]byte(o1), &h1) == nil {
					p.m1Worker = h1.Spec.Components.Worker != nil
				}
			}
			say("reusing the two-machine cluster (KEVASO_METAL_REUSE)")
			if os.Getenv("KEVASO_METAL_REDEPLOY") != "" {
				bin, err := buildKevasod(ctx, p.m1.arch)
				if err != nil {
					return nil, "", err
				}
				for _, m := range []*metalSuite{p.m1, p.m2} {
					if err := m.redeploy(ctx, bin); err != nil {
						return nil, "", err
					}
				}
				say("kevasod redeployed on both machines")
				if err := waitRuntimes(ctx, metalHost2, "cloud-hypervisor", "docker"); err != nil {
					return nil, "", err
				}
			}
			return p, "", nil
		}
		say("no two-machine cluster to reuse: making one")
	}
	if p.m1, err = reach(ctx, cfg1); err != nil {
		return nil, "", err
	}
	if p.m2, err = reach(ctx, cfg2); err != nil {
		return nil, "", err
	}
	if p.m1.arch != p.m2.arch {
		return nil, "", fmt.Errorf("the machines' CPUs differ (%s, %s): one kevasod build serves both here", p.m1.uname, p.m2.uname)
	}
	say("both machines reset to clean")

	tmp, err := os.MkdirTemp("", "kvt-metal2-")
	if err != nil {
		return nil, "", err
	}
	p.bin = filepath.Join(tmp, "kevasod")
	build := exec.CommandContext(ctx, "go", "build", "-o", p.bin, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+p.m1.arch, "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		return nil, "", fmt.Errorf("build kevasod: %v\n%s", err, b)
	}
	if !reuse {
		home := filepath.Join(tmp, "home")
		for k, v := range map[string]string{"HOME": home, "KVO_CONFIG": filepath.Join(home, ".kevaso", "config.yaml"), "KVO_TOKEN_STORE": "file", "KVO_SERVER": ""} {
			if err := os.Setenv(k, v); err != nil {
				return nil, "", err
			}
		}
	}
	lastOut := ""
	run := func(args ...string) error {
		var o bytes.Buffer
		if code := kvoadm.Run(ctx, args, strings.NewReader(""), &o, &o); code != 0 {
			return fmt.Errorf("kvoadm %s: exit %d\n%s", args[0], code, metalRedact(o.String()))
		}
		lastOut = o.String()
		return nil
	}
	ssh := func(c remote.Config) []string {
		return []string{c.SSHTarget(), "--ssh-port", strconv.Itoa(c.Port), "--ssh-key", c.KeyFile, "--host-key", c.HostKey, "--kevasod", p.bin, "--no-extra-hardening"}
	}
	// Machine 1: the system node, no worker.
	if err := run(append(append([]string{"init"}, ssh(cfg1)...), "--name", metalHost, "--cluster", "metal2",
		"--api-server", metalAPIServerFor(cfg1.ExternalIP, cfg1.Address, p.apiPort), "--external-ip", cfg1.ExternalIP)...); err != nil {
		return nil, "", err
	}
	p.recoveryKey = regexp.MustCompile(`KVR1-[A-Z0-9-]+`).FindString(lastOut)
	// kvo's own context is a plain user; the suite does an admin's work through kvo.
	if err := os.Setenv("KVO_CONFIG", metalAdminKvo(os.Getenv("HOME"), "metal2")); err != nil {
		return nil, "", err
	}
	say("kvoadm init: %s, the system node", metalHost)
	// Machine 2: a worker, joining over the external IPs.
	storage := []string{"--loop-storage", metalLoop}
	if cfg2.SpareDisk != "" {
		// Its volume group on a real disk (§0.8): kvoadm --storage-device makes it there, only on
		// an empty disk, and refuses anything else.
		storage = []string{"--storage-device", cfg2.SpareDisk}
	}
	// The stand-in internet on machine 2 (the injection tests), its CA trusted by the egress gate.
	if out, err := p.m2.d.Run(ctx, metalInetSetup, nil); err != nil {
		return nil, "", fmt.Errorf("the stand-in internet on %s: %v\n%s", metalHost2, err, out)
	}
	storage = append(storage, "--egress-extra-ca", "/etc/kevaso/test-internet-ca.pem")
	// A real pair's worker dials the context server, https://external:6443. A pair lab's
	// context server is the lab host's slot port, which m2 cannot route. m2 dials m1's
	// external address on 6443, on the external bridge.
	add := append(append(append([]string{"host", "add"}, ssh(cfg2)...), "--name", metalHost2, "--install", "worker",
		"--runtime", "cloud-hypervisor", "--runtime", "docker", "--external-ip", cfg2.ExternalIP), storage...)
	if p.apiPort != "6443" {
		add = append(add, "--server", metalAPIServer(cfg1.ExternalIP, "6443"))
	}
	if err := run(add...); err != nil {
		return nil, "", err
	}
	say("kvoadm host add: %s, a worker", metalHost2)
	if err := waitRuntimes(ctx, metalHost2, "cloud-hypervisor", "docker"); err != nil {
		return nil, "", err
	}
	var h v1.Host
	if out, code := kvoOut(ctx, "get", "host", metalHost, "-o", "json"); code != 0 || json.Unmarshal([]byte(out), &h) != nil {
		return nil, "", fmt.Errorf("host %s: %s", metalHost, out)
	}
	p.m1.suffix, p.m2.suffix = v1.ClusterSuffix([]*v1.Host{&h}), v1.ClusterSuffix([]*v1.Host{&h})
	say("%s's runtimes Ready", metalHost2)
	return p, "", nil
}

func kvoOut(ctx context.Context, args ...string) (string, int) {
	var o bytes.Buffer
	code := kvo.Run(ctx, args, nil, &o, &o)
	return o.String(), code
}

// waitRuntimes waits until a host's runtimes are Ready.
func waitRuntimes(ctx context.Context, host string, runtimes ...string) error {
	deadline := time.Now().Add(20 * time.Minute)
	for {
		var h v1.Host
		out, code := kvoOut(ctx, "get", "host", host, "-o", "json")
		if code == 0 && json.Unmarshal([]byte(out), &h) == nil {
			ready := 0
			for _, rt := range runtimes {
				switch st := h.Status.Runtimes[rt]; st.State {
				case "Ready":
					ready++
				case "Failed":
					return fmt.Errorf("%s: runtime %s failed: %s", host, rt, st.Message)
				}
			}
			if ready == len(runtimes) && hostIs(h, "Ready") {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s's runtimes %v never got Ready: %s", host, runtimes, out)
		}
		time.Sleep(10 * time.Second)
	}
}

func hostIs(h v1.Host, cond string) bool {
	for _, c := range h.Status.Conditions {
		if c.Type == cond {
			return c.Status == "True"
		}
	}
	return false
}

// ensureTwoWorkers makes machine 1 a worker too (once), and labels both hosts kvt/host=NAME so a
// test can place a silo on either.
func (p *pair) ensureTwoWorkers() {
	p.t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m1Worker {
		return
	}
	c := p.c1
	args := []string{"host", "enable-worker", c.cfg.SSHTarget(), "--ssh-port", strconv.Itoa(c.cfg.Port), "--ssh-key", c.cfg.KeyFile,
		"--host-key", c.cfg.HostKey, "--loop-storage", metalLoop, "--runtime", "cloud-hypervisor", "--runtime", "docker"}
	var o bytes.Buffer
	if code := kvoadm.Run(c.ctx, args, strings.NewReader(""), &o, &o); code != 0 {
		p.t.Fatalf("kvoadm host enable-worker %s: exit %d\n%s", metalHost, code, o.String())
	}
	c.eventually("the API is back", 3*time.Minute, func() (bool, string) { out, code := c.kvo("", "get", "hosts"); return code == 0, out })
	if err := waitRuntimes(c.ctx, metalHost, "cloud-hypervisor", "docker"); err != nil {
		p.t.Fatal(err)
	}
	for _, name := range []string{metalHost, metalHost2} {
		var h v1.Host
		if err := json.Unmarshal([]byte(c.must("", "get", "host", name, "-o", "json")), &h); err != nil {
			p.t.Fatal(err)
		}
		if h.Spec.Components.Worker == nil {
			p.t.Fatalf("%s has no worker component", name)
		}
		if h.Spec.Components.Worker.Labels == nil {
			h.Spec.Components.Worker.Labels = map[string]string{}
		}
		h.Spec.Components.Worker.Labels["kvt/host"] = name
		h.Status = v1.HostStatus{}
		b, _ := json.Marshal(&h)
		c.apply(string(b))
	}
	p.m1Worker = true
}

// on is a placement on one host (after ensureTwoWorkers).
func on(host string) string { return "  placement: { hostSelector: { kvt/host: " + host + " } }\n" }

// openOn says whether this Mac gets an HTTP answer on a machine's external IP.
// port is the one on the machine. A pair lab publishes it on the lab host when
// this machine owns that port. A check of the other machine dials that machine's
// external address on the real port. Unset, this dials the real port, which is
// what a real pair listens on.
func openOn(s *metalSuite, port int) (bool, string) {
	target, err := metalDialTarget(s.cfg.ExternalIP, s.cfg.Address, port)
	if err != nil {
		return false, err.Error()
	}
	code, body, err := fromMac("http://"+target+"/", "", 5*time.Second)
	if err != nil {
		return false, err.Error()
	}
	return code == 200, fmt.Sprintf("%d %s", code, strings.TrimSpace(body))
}

// resetPairAtEnd is TestMain's last step for the two-machine suite.
func resetPairAtEnd() int {
	if len(pairState.touched) == 0 {
		return 0
	}
	code := 0
	if os.Getenv("KEVASO_E2E_KEEP") != "" || os.Getenv("KEVASO_METAL_REUSE") != "" {
		fmt.Println("metal2: KEEPING the two-machine cluster (KEVASO_E2E_KEEP / KEVASO_METAL_REUSE)")
		return 0
	}
	for _, d := range pairState.touched {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		if err := d.Reset(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "metal2: the final reset of %s failed:\n%v\n", d.Config.SSHTarget(), err)
			code = 1
		} else {
			fmt.Printf("metal2: %s is clean\n", d.Config.SSHTarget())
		}
		cancel()
		_ = d.Close()
	}
	return code
}

// pinGoEnv fixes Go's cache directories before a test moves HOME, so later builds use the
// usual caches.
func pinGoEnv() {
	for _, k := range []string{"GOCACHE", "GOMODCACHE", "GOPATH"} {
		if os.Getenv(k) != "" {
			continue
		}
		if out, err := exec.Command("go", "env", k).Output(); err == nil {
			_ = os.Setenv(k, strings.TrimSpace(string(out)))
		}
	}
}

// buildKevasod builds kevasod from the tree for the machines' CPU.
func buildKevasod(ctx context.Context, arch string) (string, error) {
	dir, err := os.MkdirTemp("", "kvt-kevasod-")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "kevasod")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build kevasod: %v\n%s", err, b)
	}
	return bin, nil
}

// hostNamed reads a Host.
// hostReady says whether a host is Ready, for eventually: an API that doesn't answer this once
// (a TLS handshake timing out over the internet) is a "not yet", not a failure.
func (c *mt) hostReady(name string) (bool, string) {
	out, code := c.kvo("", "get", "host", name, "-o", "json")
	var h v1.Host
	if code != 0 || json.Unmarshal([]byte(out), &h) != nil {
		return false, out
	}
	return hostIs(h, "Ready"), fmt.Sprint(h.Status.Conditions)
}

func (c *mt) hostNamed(name string) *v1.Host {
	c.t.Helper()
	var h v1.Host
	if err := json.Unmarshal([]byte(c.must("", "get", "host", name, "-o", "json")), &h); err != nil {
		c.t.Fatal(err)
	}
	return &h
}
