// Package worker is the worker component of kevasod: it installs the host's runtimes, keeps the
// worker part of its Host object up to date (component, runtime states, allocatable resources), and
// runs the agent that drives the silos placed here.
package worker

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/container"
	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/builtin/kri/openshell"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/gate"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kri"
)

// Config configures the worker component.
type Config struct {
	HostName string
	Runtimes []string // runtimes to install, e.g. cloud-hypervisor
	Labels   map[string]string
	DataDir  string // for the exec key
	Storage  cloudhypervisor.StorageOptions
	Clock    clock.Clock
	Log      func(string, ...any)
	// Contact is when the heartbeat last got through, and whether a fence applies here; the agent
	// fences (stops silos that may be recreated elsewhere) when it's too old. Nil: never fence.
	Contact *Contact
	// MeshSubnet: wait for the control plane to give this host its silo subnet (on the mesh) and
	// use it; without, silos use 10.64.0.0/24.
	MeshSubnet bool
	// EgressExtraCA is a PEM file the egress gate trusts for upstream hosts, on top of the system
	// roots (a company's TLS proxy; the e2e test's stand-in internet).
	EgressExtraCA string
	// GatewayScope is how many OpenShell gateways run (host | namespace | silo; default namespace):
	// sandboxes of one gateway share its user (design §3.1).
	GatewayScope string
	// PluginsDir is where the plugins' node sides put their sockets, DIR/NAME/node.sock (default
	// kplugin.Dir): they mount the volumes of mount-reach storage classes (juicefs).
	PluginsDir string
}

// Installer is a runtime that needs setting up on the host first.
type Installer interface {
	kri.Runtime
	Install(ctx context.Context, progress func(step string)) error
}

type chInstaller struct {
	*cloudhypervisor.Runtime
	storage cloudhypervisor.StorageOptions
}

func (c chInstaller) Install(ctx context.Context, progress func(string)) error {
	return c.Runtime.Install(ctx, c.storage, progress)
}

// Arch is this machine's CPU in `uname -m` terms.
func Arch() string {
	if runtime.GOARCH == "arm64" {
		return "aarch64"
	}
	return "x86_64"
}

// execKey loads or creates the key this host uses to run commands in its silos.
func execKey(dir string) (ssh.Signer, string, error) {
	path := filepath.Join(dir, "silo-exec_ed25519")
	if b, err := os.ReadFile(path); err == nil {
		s, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return nil, "", err
		}
		return s, string(ssh.MarshalAuthorizedKey(s.PublicKey())), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	blk, err := ssh.MarshalPrivateKey(sk, "kevasod silo exec")
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, "", err
	}
	s, err := ssh.NewSignerFromKey(sk)
	if err != nil {
		return nil, "", err
	}
	return s, string(ssh.MarshalAuthorizedKey(s.PublicKey())), nil
}

// NewRuntimes builds the configured runtimes.
func NewRuntimes(cfg Config) (map[string]Installer, error) {
	out := map[string]Installer{}
	for _, name := range cfg.Runtimes {
		switch name {
		case "cloud-hypervisor":
			signer, pub, err := execKey(filepath.Join(cfg.DataDir, "ssh"))
			if err != nil {
				return nil, err
			}
			out[name] = chInstaller{Runtime: &cloudhypervisor.Runtime{
				Host: cloudhypervisor.Local{}, Arch: Arch(), ExecKey: signer, ExecPub: pub, Version: cloudhypervisor.Version,
			}, storage: cfg.Storage}
		case "docker", "podman":
			self, _ := os.Executable()
			out[name] = &container.Runtime{Host: hostexec.Local{}, Engine: name, Self: self}
		case "openshell", "openshell-container":
			driver := openshell.DriverVM
			if name == "openshell-container" {
				driver = openshell.DriverDocker
			}
			out[name] = &openshell.Runtime{Host: openshell.Local{}, Name: name, Driver: driver, Scope: cfg.GatewayScope,
				ExtraCA: cfg.EgressExtraCA, Arch: Arch()}
		default:
			return nil, fmt.Errorf("runtime %q isn't available yet (cloud-hypervisor, openshell, openshell-container are)", name)
		}
	}
	return out, nil
}

// Run installs the runtimes, keeps the Host's worker fields current, and runs the agent.
func Run(ctx context.Context, c *client.Client, cfg Config, rts map[string]Installer) {
	if cfg.Log == nil {
		cfg.Log = func(string, ...any) {}
	}
	var mu sync.Mutex
	states := map[string]v1.RuntimeStatus{}
	for name, rt := range rts {
		states[name] = v1.RuntimeStatus{State: "Installing", Version: rt.Info().Version}
	}
	// The plugins' node sides on this host: the storage classes it can mount are on its Host.
	nodes := &plugins.Registry{Dir: cfg.PluginsDir, Socket: kplugin.NodeSocket, Log: cfg.Log}
	report := func() {
		mu.Lock()
		snap := map[string]v1.RuntimeStatus{}
		for k, v := range states {
			snap[k] = v
		}
		mu.Unlock()
		if err := updateHost(ctx, c, cfg, snap, nodes.MountClasses()); err != nil && ctx.Err() == nil {
			cfg.Log("worker status: %v", err)
		}
	}
	// The control plane registers the Host (and, on the mesh, gives it a subnet); wait for it
	// before reporting worker fields and installing runtimes.
	for {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", cfg.HostName, &h); err == nil {
			if !cfg.MeshSubnet {
				break
			}
			if p, err := netip.ParsePrefix(h.Status.Network.SiloSubnet); err == nil {
				cloudhypervisor.SetNetwork(p)
				cfg.Log("silo subnet %s", p)
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	report()
	nodes.OnChange = func() { go report() }
	go nodes.Run(ctx)
	// The egress gate's CA: made on this host, its silos trust it (design §8.1, E025).
	var egressCA *gate.CA
	var upstream *x509.CertPool
	if runtime.GOOS == "linux" && cfg.DataDir != "" {
		var err error
		if egressCA, err = gate.LoadOrCreateCA(filepath.Join(cfg.DataDir, "egress-ca"), cfg.HostName); err != nil {
			cfg.Log("egress gate: %v (no injection on this host)", err)
		}
		if upstream, err = upstreamRoots(cfg.EgressExtraCA); err != nil {
			cfg.Log("egress gate: extra CA: %v", err)
		}
	}
	for _, rt := range rts { // container silos trust the host's CAs plus its egress CA
		if cr, ok := rt.(*container.Runtime); ok {
			cr.CABundle = caBundle(egressCA)
		}
	}
	var networkOnce sync.Once
	for name, rt := range rts {
		go func(name string, rt Installer) {
			// A failed install (a download cut short, a mirror down) is tried again every minute.
			for {
				cfg.Log("installing runtime %s", name)
				st := v1.RuntimeStatus{State: "Ready", Version: rt.Info().Version}
				err := rt.Install(ctx, func(step string) {
					cfg.Log("runtime %s: %s", name, step)
					mu.Lock()
					states[name] = v1.RuntimeStatus{State: "Installing", Version: st.Version, Message: step}
					mu.Unlock()
					report()
				})
				if err != nil {
					cfg.Log("runtime %s: %v (trying again in a minute)", name, err)
					st.State, st.Message = "Failed", err.Error()
				} else {
					st.EnvOutsideEngine = rt.Info().Capabilities.EnvOutsideEngine
					cfg.Log("runtime %s ready", name)
					if usesBridge(rt) { // the bridge is there now: keep its firewall current (once)
						networkOnce.Do(func() { go RunNetwork(ctx, c, cfg.HostName, egressCA, upstream, cfg.Log) })
					}
				}
				mu.Lock()
				states[name] = st
				mu.Unlock()
				report()
				if err == nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Minute):
				}
			}
		}(name, rt)
	}
	go func() { // keep allocatable and runtime states fresh
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				report()
			}
		}
	}()
	runtimes := map[string]kri.Runtime{}
	for name, rt := range rts {
		runtimes[name] = rt
	}
	a := &agent.Agent{Client: c, HostName: cfg.HostName, Runtimes: runtimes, Clock: cfg.Clock, Log: cfg.Log, Nodes: nodes,
		RuntimeReady: func(name string) bool {
			mu.Lock()
			defer mu.Unlock()
			return states[name].State == "Ready"
		}}
	if cfg.Contact != nil {
		a.LastContact, a.FenceApplies = cfg.Contact.Last, cfg.Contact.Fence
		if runtime.GOOS == "linux" {
			a.FenceDir = fence.Dir // for kevasod fence-watch, which fences even when this agent is gone
		}
	}
	if cfg.DataDir != "" {
		a.OnEndpoints = func(servers []string) {
			if err := KeepServers(cfg.DataDir, servers); err != nil {
				cfg.Log("keep the control planes' URLs: %v", err)
			}
		}
	}
	if runtime.GOOS == "linux" {
		a.Host = hostexec.Local{} // provider volumes: format once, mount
	}
	if egressCA != nil {
		a.EgressCA = egressCA.PEM
	}
	for _, rt := range rts {
		if usesBridge(rt) && runtime.GOOS == "linux" { // the local endpoint, on the silo bridge (ADR 0009)
			a.EndpointListen = net.JoinHostPort(v1.EndpointAddress, strconv.Itoa(v1.EndpointPort))
		}
	}
	a.Run(ctx)
}

// usesBridge reports whether a runtime puts its silos on the host's silo bridge (the firewall and
// the egress gate run for those).
func usesBridge(rt Installer) bool {
	switch rt.(type) {
	case chInstaller, *container.Runtime:
		return true
	}
	return false
}

// caBundle is the host's system CAs plus its egress CA, for container silos.
func caBundle(egress *gate.CA) []byte {
	b, _ := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	if egress != nil {
		b = append(append(b, '\n'), egress.PEM...)
	}
	return b
}

// updateHost makes sure the Host declares the worker component and reports its runtimes and
// allocatable resources, retrying on conflicts with the control plane's own heartbeat.
func updateHost(ctx context.Context, c *client.Client, cfg Config, states map[string]v1.RuntimeStatus, mountClasses []string) error {
	for attempt := 0; attempt < 5; attempt++ {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", cfg.HostName, &h); err != nil {
			return err
		}
		if h.Spec.Components.Worker == nil {
			w := &v1.WorkerSpec{Labels: cfg.Labels}
			for _, name := range cfg.Runtimes {
				rs := v1.RuntimeSpec{Name: name}
				if strings.HasPrefix(name, "openshell") {
					scope := cfg.GatewayScope
					if scope == "" {
						scope = openshell.ScopeNamespace
					}
					rs.Options = map[string]string{"gatewayScope": scope}
				}
				w.Runtimes = append(w.Runtimes, rs)
			}
			h.Spec.Components.Worker = w
			if err := c.Update(ctx, &h); err != nil {
				if client.IsConflict(err) {
					continue
				}
				return err
			}
		}
		h.Status.Runtimes = states
		h.Status.Allocatable = allocatable()
		h.Status.MountClasses = mountClasses
		err := c.UpdateStatus(ctx, &h)
		if client.IsConflict(err) {
			continue
		}
		return err
	}
	return errors.New("host kept changing")
}

// allocatable is what silos may use: all CPUs but one, and memory minus 1Gi for the host itself.
func allocatable() v1.Resources {
	cpus := runtime.NumCPU() - 1
	if cpus < 1 {
		cpus = 1
	}
	mem := memTotal() - 1<<30
	if mem < 512<<20 {
		mem = 512 << 20
	}
	return v1.Resources{CPU: cpus, Memory: fmt.Sprintf("%dMi", mem>>20)}
}

func memTotal() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 4 << 30 // not Linux (tests on a Mac): a plausible default
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var kb int64
		if strings.HasPrefix(sc.Text(), "MemTotal:") {
			if _, err := fmt.Sscanf(strings.TrimPrefix(sc.Text(), "MemTotal:"), "%d", &kb); err == nil {
				return kb << 10
			}
		}
	}
	return 4 << 30
}
