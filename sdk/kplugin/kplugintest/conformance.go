package kplugintest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/sdk/kplugin"
)

// Suite is what Conformance needs to exercise a plugin. Fakes and real plugins run the same suite
// (ADR 0001: fakes can't lie), always over the wire: each side is served on a socket and called
// through kplugin.Client.
type Suite struct {
	Plugin kplugin.Plugin // the controller side
	// Node is the plugin's node side, for mount-reach storage classes (nil: those mounts aren't
	// checked).
	Node kplugin.Plugin
	// Host is one of the plugin's machines, for attaching device-reach volumes.
	Host   kplugin.HostInfo
	Region string // where volumes are created
	// MountDir is a folder for the node side's mounts (default: a temporary one).
	MountDir string
	// Classes limits the storage classes exercised (default: every one the plugin serves).
	Classes []string
	// Patience is how long a call answering ErrInProgress is asked again (default 10s).
	Patience time.Duration
}

var topologies = map[string]bool{"": true, kplugin.TopologyHost: true, kplugin.TopologyZone: true, kplugin.TopologyRegion: true, kplugin.TopologyGlobal: true}
var reaches = map[string]bool{"": true, kplugin.ReachDevice: true, kplugin.ReachMount: true}
var follows = map[string]bool{"": true, kplugin.FollowsHost: true, kplugin.FollowsRegion: true, kplugin.FollowsGlobal: true}

// Conformance checks that a plugin keeps the protocol's promises: what Info says, services it
// doesn't serve answering ErrUnsupported, and for each storage class the whole life of a volume,
// every call idempotent (create, attach or mount, let go, delete; deleting twice is NotFound).
func Conformance(t *testing.T, s Suite) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := ServeForTest(t, s.Plugin)
	patience := s.Patience
	if patience <= 0 {
		patience = 10 * time.Second
	}
	// again asks while the plugin says it's still at it.
	again := func(call func() error) error {
		deadline := time.Now().Add(patience)
		for {
			err := call()
			if !errors.Is(err, kplugin.ErrInProgress) || time.Now().After(deadline) {
				return err
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	info, err := c.Info(ctx)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	t.Run("info", func(t *testing.T) {
		if info.Name == "" || info.Protocol != kplugin.Protocol {
			t.Errorf("name %q, protocol %q", info.Name, info.Protocol)
		}
		seen := map[string]bool{}
		for _, cl := range append(append([]kplugin.Class(nil), info.Storage...), info.LoadBalancers...) {
			if cl.Name == "" || seen[cl.Name] {
				t.Errorf("class name %q empty or twice", cl.Name)
			}
			seen[cl.Name] = true
		}
		for _, cl := range info.Storage {
			if !topologies[cl.Topology] || !reaches[cl.Reach] {
				t.Errorf("storage class %s: topology %q, reach %q", cl.Name, cl.Topology, cl.Reach)
			}
		}
		_, addresses := s.Plugin.(kplugin.Addresses)
		for _, cl := range info.LoadBalancers {
			if !follows[cl.Follows] {
				t.Errorf("load-balancer class %s: follows %q", cl.Name, cl.Follows)
			}
			if cl.Exclusive && cl.NodePorts && !cl.Announce {
				t.Errorf("load-balancer class %s is exclusive, yet a balancer in front (node ports) can serve many services on one address", cl.Name)
			}
			if cl.SendsFrom && cl.NodePorts && !cl.Announce {
				t.Errorf("load-balancer class %s sends from its address, yet a balancer in front (node ports) has it on no host", cl.Name)
			}
			if !addresses {
				t.Errorf("load-balancer class %s: a plugin serving load balancers serves Addresses too (ReleaseAddress deletes an IP's balancer)", cl.Name)
			}
		}
	})

	t.Run("unserved services", func(t *testing.T) {
		if _, ok := s.Plugin.(kplugin.HostDescriber); !ok {
			if _, err := c.DescribeHosts(ctx, nil); !errors.Is(err, kplugin.ErrUnsupported) {
				t.Errorf("hosts: %v", err)
			}
		}
		if _, ok := s.Plugin.(kplugin.LoadBalancers); !ok {
			if err := c.DeleteLoadBalancer(ctx, kplugin.LoadBalancerRef{ID: "x"}); !errors.Is(err, kplugin.ErrUnsupported) {
				t.Errorf("load balancers: %v", err)
			}
		}
		if _, ok := s.Plugin.(kplugin.Addresses); !ok {
			if err := c.ReleaseAddress(ctx, kplugin.AddressRef{ID: "x"}); !errors.Is(err, kplugin.ErrUnsupported) {
				t.Errorf("addresses: %v", err)
			}
		}
		if _, ok := s.Plugin.(kplugin.Volumes); !ok {
			if err := c.DeleteVolume(ctx, kplugin.VolumeRef{Handle: "x"}); !errors.Is(err, kplugin.ErrUnsupported) {
				t.Errorf("volumes: %v", err)
			}
		}
		if _, ok := s.Plugin.(kplugin.DNS); !ok {
			if err := c.DeleteRecord(ctx, kplugin.Record{Name: "x"}); !errors.Is(err, kplugin.ErrUnsupported) {
				t.Errorf("dns: %v", err)
			}
		}
		if _, ok := s.Plugin.(kplugin.Node); !ok {
			if err := c.UnmountVolume(ctx, kplugin.NodeMount{Path: "/x"}); !errors.Is(err, kplugin.ErrUnsupported) {
				t.Errorf("node: %v", err)
			}
		}
	})

	var node *kplugin.Client
	mounts := map[string]bool{}
	for _, cl := range info.Storage {
		mounts[cl.Name] = cl.Mounted()
	}
	if s.Node != nil {
		node = ServeForTest(t, s.Node)
		t.Run("node info", func(t *testing.T) {
			ni, err := node.Info(ctx)
			if err != nil || ni.Name != info.Name {
				t.Fatalf("node side info %+v %v (want the same name as the controller side)", ni, err)
			}
			for _, cl := range ni.Storage {
				if m, ok := mounts[cl.Name]; !ok || !m {
					t.Errorf("node side serves %s, which the controller side doesn't serve as a mount class", cl.Name)
				}
			}
		})
	}

	// Every class that reserves: an address held apart from a load balancer, idempotent by ID,
	// released once (again is NotFound). A class that can't says so (Unsupported).
	for _, cl := range info.LoadBalancers {
		if _, ok := s.Plugin.(kplugin.Addresses); !ok {
			break
		}
		cl := cl
		t.Run("address "+cl.Name, func(t *testing.T) {
			r := kplugin.AddressReservation{Class: cl.Name, ID: "c0nf0rmance-ip-uid", Namespace: "conformance", Name: "ip", Region: s.Region}
			var st kplugin.AddressStatus
			err := again(func() (err error) { st, err = c.ReserveAddress(ctx, r); return })
			if !cl.Reserve {
				if !errors.Is(err, kplugin.ErrUnsupported) {
					t.Fatalf("reserve on %s, which doesn't: %+v %v (want Unsupported)", cl.Name, st, err)
				}
				return
			}
			if err != nil || st.Address == "" {
				t.Fatalf("reserve: %+v %v", st, err)
			}
			var st2 kplugin.AddressStatus
			if err := again(func() (err error) { st2, err = c.ReserveAddress(ctx, r); return }); err != nil || st2.Address != st.Address {
				t.Fatalf("reserve again: %+v %v (want the same address %s)", st2, err, st.Address)
			}
			ref := kplugin.AddressRef{Class: cl.Name, ID: r.ID, Address: st.Address, Handle: st.Handle}
			if err := again(func() error { return c.ReleaseAddress(ctx, ref) }); err != nil {
				t.Fatalf("release: %v", err)
			}
			if err := again(func() error { return c.ReleaseAddress(ctx, ref) }); !errors.Is(err, kplugin.ErrNotFound) {
				t.Fatalf("release again: %v (want NotFound)", err)
			}
		})
	}

	// A shared balancer behind one address: every service's ports on it, each with its own
	// backends; the same address as ports come and go; parked with none; gone on release.
	for _, cl := range info.LoadBalancers {
		if cl.Exclusive || !cl.NodePorts || s.Host.ID == "" {
			continue
		}
		cl := cl
		t.Run("balancer "+cl.Name, func(t *testing.T) {
			lb := kplugin.LoadBalancer{Class: cl.Name, ID: "c0nf0rmance-shared-ip-uid", Namespace: "conformance", Name: "default-" + cl.Name,
				Backends: []kplugin.HostInfo{s.Host}, Ports: []kplugin.Port{
					{Name: "http", Protocol: "TCP", Port: 80, NodePort: 30000, Service: "silo/a", Backends: []kplugin.HostInfo{s.Host}},
					{Name: "rpc", Protocol: "TCP", Port: 8545, NodePort: 30001, Service: "silo/b", Backends: []kplugin.HostInfo{s.Host}}}}
			var st kplugin.LoadBalancerStatus
			if err := again(func() (err error) { st, err = c.EnsureLoadBalancer(ctx, lb); return }); err != nil || st.Address == "" {
				t.Fatalf("ensure: %+v %v", st, err)
			}
			one := lb
			one.Ports = lb.Ports[:1]
			var st2 kplugin.LoadBalancerStatus
			if err := again(func() (err error) { st2, err = c.EnsureLoadBalancer(ctx, one); return }); err != nil || st2.Address != st.Address {
				t.Fatalf("a service gone: %+v %v (want the same address %s)", st2, err, st.Address)
			}
			bad := one
			bad.Annotations = map[string]string{info.Name + ".kevaso.com/c0nf0rmance-no-such-knob": "x"}
			if _, err := c.EnsureLoadBalancer(ctx, bad); err == nil {
				t.Fatalf("an unknown annotation in its domain was taken")
			}
			parked := kplugin.LoadBalancer{Class: cl.Name, ID: lb.ID, Namespace: lb.Namespace, Name: lb.Name}
			var st3 kplugin.LoadBalancerStatus
			if err := again(func() (err error) { st3, err = c.EnsureLoadBalancer(ctx, parked); return }); err != nil || st3.Address != st.Address {
				t.Fatalf("parked: %+v %v (want the address %s kept)", st3, err, st.Address)
			}
			ref := kplugin.AddressRef{Class: cl.Name, ID: lb.ID, Address: st.Address}
			if err := again(func() error { return c.ReleaseAddress(ctx, ref) }); err != nil {
				t.Fatalf("release: %v", err)
			}
			if err := again(func() error { return c.ReleaseAddress(ctx, ref) }); !errors.Is(err, kplugin.ErrNotFound) {
				t.Fatalf("release again: %v (want NotFound)", err)
			}
		})
	}

	if _, ok := s.Plugin.(kplugin.Volumes); !ok {
		return
	}
	want := map[string]bool{}
	for _, n := range s.Classes {
		want[n] = true
	}
	for _, cl := range info.Storage {
		if len(want) > 0 && !want[cl.Name] {
			continue
		}
		cl := cl
		t.Run("volume "+cl.Name, func(t *testing.T) {
			v := kplugin.Volume{Class: cl.Name, ID: "c0nf0rmance-uid/data", Name: "kvo-conformance-data", SizeBytes: 1 << 30, Region: s.Region}
			var st kplugin.VolumeStatus
			if err := again(func() (err error) { st, err = c.EnsureVolume(ctx, v); return }); err != nil || st.Handle == "" {
				t.Fatalf("ensure: %+v %v", st, err)
			}
			var st2 kplugin.VolumeStatus
			if err := again(func() (err error) { st2, err = c.EnsureVolume(ctx, v); return }); err != nil || st2.Handle != st.Handle {
				t.Fatalf("ensure again: %+v %v (want the same handle %s)", st2, err, st.Handle)
			}
			// The silo's size grew: same volume, and a plugin that enforces sizes enforces the new one.
			grown := v
			grown.SizeBytes = 2 << 30
			var st3 kplugin.VolumeStatus
			if err := again(func() (err error) { st3, err = c.EnsureVolume(ctx, grown); return }); err != nil || st3.Handle != st.Handle {
				t.Fatalf("ensure grown: %+v %v (want the same handle %s)", st3, err, st.Handle)
			}
			if st3.SizeEnforced && st3.SizeBytes < grown.SizeBytes {
				t.Fatalf("ensure grown: enforces %d bytes, asked for %d", st3.SizeBytes, grown.SizeBytes)
			}
			if cl.Mounted() {
				if cl.OwnHostsOnly {
					t.Logf("%s is mounted by the node side yet only reaches the plugin's machines", cl.Name)
				}
				if node == nil {
					t.Logf("no node side given: mounting %s not checked", cl.Name)
				} else {
					dir := s.MountDir
					if dir == "" {
						dir = t.TempDir()
					}
					m := kplugin.NodeMount{Class: cl.Name, Handle: st.Handle, ID: v.ID, Path: filepath.Join(dir, "c0nf0rmance-uid", "data")}
					for i := 0; i < 2; i++ {
						if err := again(func() error { return node.MountVolume(ctx, m) }); err != nil {
							t.Fatalf("mount (%d): %v", i+1, err)
						}
					}
					for i := 0; i < 2; i++ {
						if err := again(func() error { return node.UnmountVolume(ctx, m) }); err != nil {
							t.Fatalf("unmount (%d): %v", i+1, err)
						}
					}
				}
			} else {
				a := kplugin.Attachment{Class: cl.Name, Handle: st.Handle, Host: s.Host}
				var at kplugin.AttachmentStatus
				if err := again(func() (err error) { at, err = c.AttachVolume(ctx, a); return }); err != nil || at.Device == "" {
					t.Fatalf("attach: %+v %v", at, err)
				}
				var at2 kplugin.AttachmentStatus
				if err := again(func() (err error) { at2, err = c.AttachVolume(ctx, a); return }); err != nil || at2.Device != at.Device {
					t.Fatalf("attach again: %+v %v", at2, err)
				}
				for i := 0; i < 2; i++ {
					if err := again(func() error { return c.DetachVolume(ctx, a) }); err != nil {
						t.Fatalf("detach (%d): %v", i+1, err)
					}
				}
			}
			ref := kplugin.VolumeRef{Class: cl.Name, Handle: st.Handle}
			if err := again(func() error { return c.DeleteVolume(ctx, ref) }); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if err := again(func() error { return c.DeleteVolume(ctx, ref) }); !errors.Is(err, kplugin.ErrNotFound) {
				t.Fatalf("delete again: %v (want NotFound)", err)
			}
		})
	}
}

// ServeForTest serves p on a socket in a short temporary folder (unix socket paths are short) until
// the test ends, and returns a client for it.
func ServeForTest(t testing.TB, p kplugin.Plugin) *kplugin.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "kpl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "plugin.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = kplugin.Serve(ctx, sock, p) }()
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	c := kplugin.Dial(sock)
	t.Cleanup(func() { _ = c.Close(); cancel(); <-done })
	return c
}
