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
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	mu       sync.Mutex
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
	say := func(f string, a ...any) { fmt.Printf("metal2: "+f+"\n", a...) }
	p = &metalPair{}
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
	home := filepath.Join(tmp, "home")
	for k, v := range map[string]string{"HOME": home, "KVO_CONFIG": filepath.Join(home, ".kevaso", "config.yaml"), "KVO_TOKEN_STORE": "file", "KVO_SERVER": ""} {
		if err := os.Setenv(k, v); err != nil {
			return nil, "", err
		}
	}
	run := func(args ...string) error {
		var o bytes.Buffer
		if code := kvoadm.Run(ctx, args, strings.NewReader(""), &o, &o); code != 0 {
			return fmt.Errorf("kvoadm %s: exit %d\n%s", args[0], code, metalRedact(o.String()))
		}
		return nil
	}
	ssh := func(c remote.Config) []string {
		return []string{c.SSHTarget(), "--ssh-port", strconv.Itoa(c.Port), "--ssh-key", c.KeyFile, "--host-key", c.HostKey, "--kevasod", p.bin, "--no-extra-hardening"}
	}
	// Machine 1: the system node, no worker.
	if err := run(append(append([]string{"init"}, ssh(cfg1)...), "--name", metalHost, "--cluster", "metal2",
		"--api-server", "https://"+net.JoinHostPort(cfg1.ExternalIP, "6443"), "--external-ip", cfg1.ExternalIP)...); err != nil {
		return nil, "", err
	}
	say("kvoadm init: %s, the system node", metalHost)
	// Machine 2: a worker, joining over the external IPs.
	storage := []string{"--loop-storage", metalLoop}
	if cfg2.SpareDisk != "" {
		// Its volume group on a real disk, the way Kevaso supports one: made by the operator
		// (here the harness, only on the spare disk and only when it's empty); the runtime finds it.
		if out, err := p.m2.d.Run(ctx, spareVG(cfg2.SpareDisk), nil); err != nil {
			return nil, "", fmt.Errorf("the volume group on %s: %v\n%s", cfg2.SpareDisk, err, out)
		}
		storage = nil
		say("volume group kevaso made on %s", cfg2.SpareDisk)
	}
	if err := run(append(append(append([]string{"host", "add"}, ssh(cfg2)...), "--name", metalHost2, "--install", "worker",
		"--runtime", "cloud-hypervisor", "--runtime", "docker", "--external-ip", cfg2.ExternalIP), storage...)...); err != nil {
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
			if ready == len(runtimes) && meta(h, "Ready") {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s's runtimes %v never got Ready: %s", host, runtimes, out)
		}
		time.Sleep(10 * time.Second)
	}
}

func meta(h v1.Host, cond string) bool {
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

// openOn says whether this Mac gets an HTTP answer on a machine's external IP and port.
func openOn(s *metalSuite, port int) (bool, string) {
	code, body, err := fromMac(fmt.Sprintf("http://%s:%d/", s.cfg.ExternalIP, port), "", 5*time.Second)
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
	if os.Getenv("KEVASO_E2E_KEEP") != "" {
		fmt.Println("metal2: KEEPING the two-machine cluster (KEVASO_E2E_KEEP)")
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

// spareVG makes the kevaso volume group on the spare disk, only when the disk is whole, unmounted
// and has nothing on it (no partitions, holders or signatures).
func spareVG(disk string) string {
	return `set -e; d=` + disk + `
[ -b "$d" ] || { echo "$d: no such disk" >&2; exit 1; }
[ "$(lsblk -nr -o NAME "$d" | wc -l)" = 1 ] || { echo "$d has partitions or holders" >&2; exit 1; }
[ "$(lsblk -dnr -o TYPE "$d")" = disk ] || { echo "$d isn't a whole disk" >&2; exit 1; }
! lsblk -nr -o MOUNTPOINT "$d" | grep -q . || { echo "$d is mounted" >&2; exit 1; }
[ -z "$(wipefs -n "$d")" ] || { echo "$d isn't empty: $(wipefs -n "$d" | tr '\n' ' ')" >&2; exit 1; }
command -v pvcreate >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq lvm2
pvcreate -q "$d" && vgcreate -q kevaso "$d"`
}

// hostNamed reads a Host.
func (c *mt) hostNamed(name string) *v1.Host {
	c.t.Helper()
	var h v1.Host
	if err := json.Unmarshal([]byte(c.must("", "get", "host", name, "-o", "json")), &h); err != nil {
		c.t.Fatal(err)
	}
	return &h
}
