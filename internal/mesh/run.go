package mesh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	v1 "kevaso.com/core/api/v1"
)

// LoadKey reads a WireGuard private key from path, or makes one (0600). It never leaves the host.
func LoadKey(path string) (wgtypes.Key, error) {
	if b, err := os.ReadFile(path); err == nil {
		return wgtypes.ParseKey(strings.TrimSpace(string(b)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return wgtypes.Key{}, err
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return k, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return k, err
	}
	return k, os.WriteFile(path, []byte(k.String()+"\n"), 0o600)
}

// Agent keeps one host on the mesh: it publishes the host's public keys, and applies the plan
// whenever a Host changes (and every 30s, to repair drift).
type Agent struct {
	Client   *client.Client
	HostName string
	Dir      string // keys: DIR/kevaso0.key, DIR/kevaso1.key
	Log      func(string, ...any)
	// Apply defaults to the kernel; tests record instead.
	Apply func(Desired, wgtypes.Key, wgtypes.Key) error
}

// Run runs until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	if a.Apply == nil {
		a.Apply = Apply
	}
	if a.Log == nil {
		a.Log = func(string, ...any) {}
	}
	outer, err := LoadKey(filepath.Join(a.Dir, Outer+".key"))
	if err != nil {
		return err
	}
	inner, err := LoadKey(filepath.Join(a.Dir, Inner+".key"))
	if err != nil {
		return err
	}
	hosts := informer.New(a.Client, "Host")
	changed := make(chan struct{}, 1)
	hosts.AddHandler(func(informer.Key) {
		select {
		case changed <- struct{}{}:
		default:
		}
	})
	go hosts.Run(ctx)
	if !hosts.WaitSynced(ctx) {
		return ctx.Err()
	}
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	var last string
	for {
		if err := a.publish(ctx, outer, inner); err != nil && ctx.Err() == nil {
			a.Log("mesh: publish keys: %v", err)
		}
		var hs []*v1.Host
		for _, o := range hosts.List() {
			hs = append(hs, o.(*v1.Host))
		}
		if d, err := Plan(a.HostName, hs); err == nil {
			if err := a.Apply(d, outer, inner); err != nil {
				a.Log("mesh: %v", err)
			} else if s := summary(d); s != last {
				a.Log("mesh: %s", s)
				last = s
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
		case <-tick.C:
		}
	}
}

// publish puts the host's public keys on its Host status (once they're there, nothing to do).
func (a *Agent) publish(ctx context.Context, outer, inner wgtypes.Key) error {
	for attempt := 0; attempt < 5; attempt++ {
		var h v1.Host
		if err := a.Client.Get(ctx, "Host", "", a.HostName, &h); err != nil {
			return err
		}
		n := &h.Status.Network
		wantInner := ""
		if h.Spec.Network.BehindNAT {
			wantInner = inner.PublicKey().String()
		}
		if n.PublicKey == outer.PublicKey().String() && n.InnerPublicKey == wantInner {
			return nil
		}
		n.PublicKey, n.InnerPublicKey = outer.PublicKey().String(), wantInner
		err := a.Client.UpdateStatus(ctx, &h)
		if !client.IsConflict(err) {
			return err
		}
	}
	return errors.New("host kept changing")
}

func summary(d Desired) string {
	var b strings.Builder
	b.WriteString(d.Outer.Address)
	for _, p := range d.Outer.Peers {
		b.WriteString(" " + p.Host)
		if p.Endpoint == "" {
			b.WriteString("(dials in)")
		}
	}
	if d.Inner != nil {
		b.WriteString("; end-to-end via relay " + d.Relay + " to")
		for _, p := range d.Inner.Peers {
			b.WriteString(" " + p.Host)
		}
	}
	if d.Forward {
		b.WriteString("; relaying")
	}
	return b.String()
}
