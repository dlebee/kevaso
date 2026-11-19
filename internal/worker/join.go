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
	"kevaso.com/core/internal/boottime"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/pki"
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
// reuses the certificate. A stored certificate the control plane refuses because this host was
// removed is enrolled again when a join token is present: the old pki directory is moved aside
// to a dated name and is not deleted. Without a token, the error names that directory and
// kvoadm host add.
func Join(ctx context.Context, cfg JoinConfig) (*client.Client, error) {
	ca, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("cluster CA: %w", err)
	}
	dir := filepath.Join(cfg.DataDir, "pki")
	certPath, keyPath := filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key")
	cert, key, loadErr := loadHostPair(certPath, keyPath)
	needEnroll := false
	switch {
	case loadErr == nil && certificateExpired(cert, time.Now()): // an expired certificate is not reused
		if _, err := os.Stat(cfg.TokenFile); err != nil {
			return nil, fmt.Errorf("host %s certificate in %s has expired. Join again with kvoadm host add", cfg.HostName, dir)
		}
		if err := movePKIAside(dir, "expired"); err != nil { // never deleted: the old key stays under a dated name
			return nil, fmt.Errorf("moving %s aside: %w", dir, err)
		}
		needEnroll = true
	case loadErr == nil:
		c, err := client.NewTLSEndpoints(Servers(cfg.Server, cfg.DataDir), ca, cert, key)
		if err != nil {
			return nil, err
		}
		if !certificateRemoved(ctx, c, cfg.HostName) { // any other error keeps the stored certificate
			return c, nil
		}
		if _, err := os.Stat(cfg.TokenFile); err != nil {
			return nil, fmt.Errorf("host %s was removed from the cluster; its certificate in %s is refused. Move %s aside and join again with kvoadm host add", cfg.HostName, dir, dir)
		}
		if err := movePKIAside(dir, "removed"); err != nil { // never deleted: the old key stays under a dated name
			return nil, fmt.Errorf("moving %s aside: %w", dir, err)
		}
		needEnroll = true
	case os.IsNotExist(loadErr):
		needEnroll = true
	default:
		return nil, loadErr
	}
	if needEnroll {
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

// certificateRemoved reports the distinct removal 401. A connection error, or any other
// status, is not this: the stored certificate stays in use.
func certificateRemoved(ctx context.Context, c *client.Client, host string) bool {
	var h v1.Host
	return client.HostWasRemoved(c.Get(ctx, "Host", "", host, &h))
}

// certificateExpired reports whether the stored certificate is past its NotAfter. A PEM that
// isn't a certificate is not this: Join reports the parse error instead of moving it aside.
func certificateExpired(pemBytes []byte, now time.Time) bool {
	_, na, ok := pki.CertificateLifetime(pemBytes)
	return ok && !now.Before(na)
}

// movePKIAside renames dir to a dated sibling (pki.removed-…, pki.expired-…). It does not delete it.
func movePKIAside(dir, why string) error {
	if why == "" {
		why = "removed"
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	aside := dir + "." + why + "-" + stamp
	if _, err := os.Stat(aside); err == nil {
		aside = dir + "." + why + "-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return os.Rename(dir, aside)
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
	unixNano  atomic.Int64
	boot      atomic.Int64 // boottime reading + 1 (0: none yet)
	fence     atomic.Int32 // 0: not decided yet, 1: no, 2: yes
	onRemoved atomic.Value // func(): this host's certificate was refused as removed
}

// OnRemoved is called once, from Heartbeat, when the control plane says this host was removed.
func (c *Contact) OnRemoved(fn func()) {
	if c != nil && fn != nil {
		c.onRemoved.Store(fn)
	}
}

func (c *Contact) fireRemoved() {
	if c == nil {
		return
	}
	fn, _ := c.onRemoved.Load().(func())
	if fn != nil {
		fn()
	}
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

// Mark records a successful contact: when it was sent, on the wall clock and on the boot clock
// (boottime.Now), which the fence counts silence on (K-072).
func (c *Contact) Mark(t time.Time, boot time.Duration) {
	c.unixNano.Store(t.UnixNano())
	c.boot.Store(int64(boot) + 1)
}

// LastBoot is the boot clock's reading at the last successful contact; false if none yet.
func (c *Contact) LastBoot() (time.Duration, bool) {
	n := c.boot.Load()
	return time.Duration(n - 1), n != 0
}

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
	// K-108: a beat sent while held (the judge says nothing from the control plane may be applied:
	// it may be a system node behind what this worker saw) is no fence contact, and says so
	// (ReasonWorkerHeld) so the control plane doesn't count it either; a beat whose answer left
	// the worker held is no fence contact. Else a worker reaching only a stale system node never
	// fences while the live control plane restarts its opted-in silos elsewhere.
	held := func() bool {
		h, ok := c.ControlPlane.(interface{ Held() bool })
		return ok && h.Held()
	}
	removed := false
	noteRemoved := func(err error) bool {
		if !client.HostWasRemoved(err) {
			return false
		}
		removed = true
		log("host %s was removed from the cluster: %v", host, err)
		if contact != nil {
			contact.fireRemoved()
		}
		return true
	}
	tick := func() {
		for attempt := 0; attempt < 5; attempt++ {
			var h v1.Host
			if err := c.Get(ctx, "Host", "", host, &h); err != nil {
				if noteRemoved(err) || ctx.Err() != nil {
					return
				}
				log("heartbeat: %v", err)
				return
			}
			now, sentBoot := clk.Now().UTC(), boottime.Now()
			heldBefore := held()
			reason, msg := "WorkerUp", "kevasod reporting"
			if heldBefore {
				reason, msg = hostctl.ReasonWorkerHeld, "kevasod reporting, held (ControlPlaneBehind): not a contact"
			}
			h.Status.Version = version.Version
			meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: reason,
				Message: msg, ObservedGeneration: h.Generation}, now.Truncate(time.Second))
			// The server stamps it on receipt (K-106); what is sent never equals what was read, so
			// even a server that took it as sent would see the beat.
			h.Status.LastHeartbeat = hostctl.HeartbeatStamp(h.Status.LastHeartbeat, now)
			err := c.UpdateStatus(ctx, &h)
			if client.IsConflict(err) {
				continue
			}
			if err == nil && contact != nil && !heldBefore && !held() {
				// When it was SENT, not when the answer came: the control plane's count starts at
				// its arrival, so the agent's always ends first (§0.7, silo.StopMargin).
				contact.Mark(now, sentBoot)
			}
			if noteRemoved(err) {
				return
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
		if removed { // the removal is final: this loop does not retry it
			return
		}
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
