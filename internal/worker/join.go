package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/version"
)

// JoinConfig is a worker-only host joining a cluster (kvoadm host add sets these files up).
type JoinConfig struct {
	HostName  string
	Server    string // the control plane's API, e.g. https://203.0.113.10:6443; several, comma-separated, fail over
	CAFile    string // the cluster CA (pinned)
	TokenFile string // the one-time join token; removed once used
	DataDir   string // the host's key and certificate go to DataDir/pki
}

// Join returns a client authenticated as this host. The first time it enrolls with the join token
// (the key is made here and never leaves; research E019) and keeps the certificate; afterwards it
// reuses the certificate.
func Join(ctx context.Context, cfg JoinConfig) (*client.Client, error) {
	ca, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("cluster CA: %w", err)
	}
	dir := filepath.Join(cfg.DataDir, "pki")
	certPath, keyPath := filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key")
	cert, cerr := os.ReadFile(certPath)
	key, kerr := os.ReadFile(keyPath)
	if cerr != nil || kerr != nil {
		tok, err := os.ReadFile(cfg.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("not joined yet, and no join token: %w", err)
		}
		anon, err := client.NewTLSEndpoints(client.SplitServers(cfg.Server), ca, nil, nil)
		if err != nil {
			return nil, err
		}
		cred, err := anon.Enroll(ctx, strings.TrimSpace(string(tok)), cfg.HostName, "worker")
		if err != nil {
			return nil, fmt.Errorf("join: %w", err)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, cred.Key, 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(certPath, cred.Certificate, 0o644); err != nil {
			return nil, err
		}
		_ = os.Remove(cfg.TokenFile) // used up anyway
		cert, key = cred.Certificate, cred.Key
	}
	return client.NewTLSEndpoints(Servers(cfg.Server, cfg.DataDir), ca, cert, key)
}

// serversFile keeps the control planes the agent learned from the system nodes (ServersFile).
const serversFile = "servers"

// Servers are the control planes to use: --server's, then the ones learned since (KeepServers),
// so a worker set up before the other system nodes joined still finds one when its first is lost,
// across its own restarts too.
func Servers(flag, dataDir string) []string {
	out := client.SplitServers(flag)
	b, err := os.ReadFile(filepath.Join(dataDir, "pki", serversFile))
	if err != nil {
		return out
	}
	for _, s := range strings.Fields(string(b)) {
		known := false
		for _, x := range out {
			known = known || x == s
		}
		if !known && strings.HasPrefix(s, "https://") {
			out = append(out, s)
		}
	}
	return out
}

// KeepServers writes the control planes the agent knows, one per line, for Servers.
func KeepServers(dataDir string, servers []string) error {
	p := filepath.Join(dataDir, "pki", serversFile)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(servers, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Contact remembers when this host last reached the control plane (the agent fences by it), and
// whether a fence applies here at all (fence.Applies).
type Contact struct {
	unixNano atomic.Int64
	fence    atomic.Int32 // 0: not decided yet, 1: no, 2: yes
}

// SetFence records whether this host needs fencing.
func (c *Contact) SetFence(applies bool) {
	v := int32(1)
	if applies {
		v = 2
	}
	c.fence.Store(v)
}

// Fence is what SetFence last said; known false until it was called.
func (c *Contact) Fence() (applies, known bool) {
	v := c.fence.Load()
	return v == 2, v != 0
}

// Mark records a successful contact.
func (c *Contact) Mark(t time.Time) { c.unixNano.Store(t.UnixNano()) }

// Last is the last successful contact (zero if none yet).
func (c *Contact) Last() time.Time {
	if n := c.unixNano.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// DefaultHeartbeat is how often a worker reports (kevasod worker --heartbeat): well under the
// agent's FenceAfter, so a healthy host never fences.
const DefaultHeartbeat = 10 * time.Second

// Heartbeat keeps this host's Ready condition and lastHeartbeat fresh: the control plane's host
// lease reads them (a host that stops reporting is lost). Each success is marked on contact.
func Heartbeat(ctx context.Context, c *client.Client, host string, every time.Duration, clk clock.Clock, log func(string, ...any), contact *Contact) {
	tick := func() {
		for attempt := 0; attempt < 5; attempt++ {
			var h v1.Host
			if err := c.Get(ctx, "Host", "", host, &h); err != nil {
				if ctx.Err() == nil {
					log("heartbeat: %v", err)
				}
				return
			}
			now := clk.Now().UTC()
			h.Status.Version = version.Version
			meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp",
				Message: "kevasod reporting", ObservedGeneration: h.Generation}, now.Truncate(time.Second))
			hb := now.Truncate(time.Second)
			h.Status.LastHeartbeat = &hb
			err := c.UpdateStatus(ctx, &h)
			if client.IsConflict(err) {
				continue
			}
			if err == nil && contact != nil {
				contact.Mark(clk.Now())
			}
			if err != nil && ctx.Err() == nil {
				log("heartbeat: %v", err)
			}
			return
		}
	}
	tick()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// ErrNoHost: kvoadm host add creates the Host before the worker starts.
var ErrNoHost = errors.New("this host isn't registered (kvoadm host add creates it)")
