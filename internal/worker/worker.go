// Package worker is the worker component of kevasod: it installs the host's runtimes, keeps the
// worker part of its Host object up to date (component, runtime states, allocatable resources), and
// runs the agent that drives the silos placed here.
package worker

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
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
	// Contact, on a worker-only host, is when the heartbeat last got through; the agent fences
	// (stops silos that may be recreated elsewhere) when it's too old. Nil: never fence (the
	// control plane's own host).
	Contact *Contact
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
		default:
			return nil, fmt.Errorf("runtime %q isn't available yet (M3 has cloud-hypervisor)", name)
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
	report := func() {
		mu.Lock()
		snap := map[string]v1.RuntimeStatus{}
		for k, v := range states {
			snap[k] = v
		}
		mu.Unlock()
		if err := updateHost(ctx, c, cfg, snap); err != nil && ctx.Err() == nil {
			cfg.Log("worker status: %v", err)
		}
	}
	// The control plane registers the Host; wait for it before reporting worker fields.
	for {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", cfg.HostName, &h); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	report()
	for name, rt := range rts {
		go func(name string, rt Installer) {
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
				cfg.Log("runtime %s: %v", name, err)
				st.State, st.Message = "Failed", err.Error()
			} else {
				cfg.Log("runtime %s ready", name)
			}
			mu.Lock()
			states[name] = st
			mu.Unlock()
			report()
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
	a := &agent.Agent{Client: c, HostName: cfg.HostName, Runtimes: runtimes, Clock: cfg.Clock, Log: cfg.Log}
	if cfg.Contact != nil {
		a.LastContact = cfg.Contact.Last
	}
	a.Run(ctx)
}

// updateHost makes sure the Host declares the worker component and reports its runtimes and
// allocatable resources, retrying on conflicts with the control plane's own heartbeat.
func updateHost(ctx context.Context, c *client.Client, cfg Config, states map[string]v1.RuntimeStatus) error {
	for attempt := 0; attempt < 5; attempt++ {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", cfg.HostName, &h); err != nil {
			return err
		}
		if h.Spec.Components.Worker == nil {
			w := &v1.WorkerSpec{Labels: cfg.Labels}
			for _, name := range cfg.Runtimes {
				w.Runtimes = append(w.Runtimes, v1.RuntimeSpec{Name: name})
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
