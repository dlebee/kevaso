package kplugin_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

type infoOnly struct{}

func (infoOnly) Info(context.Context) (kplugin.Info, error) { return kplugin.Info{Name: "bare"}, nil }

func serve(t *testing.T, p kplugin.Plugin) *kplugin.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "kpl") // short: unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "plugin.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = kplugin.Serve(ctx, sock, p) }()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return kplugin.Dial(sock)
}

func TestWireRoundTrip(t *testing.T) {
	ctx := context.Background()
	f := kplugintest.New()
	f.Machines["203.0.113.5"] = kplugin.HostInfo{ID: "42", Region: "ca-central", PrivateAddress: "192.168.1.5"}
	f.DetachSlow = 1
	c := serve(t, f)

	info, err := c.Info(ctx)
	if err != nil || info.Name != "fake" || info.Protocol != kplugin.Protocol || len(info.LoadBalancers) != 2 {
		t.Fatalf("info %+v %v", info, err)
	}
	hs, err := c.DescribeHosts(ctx, []kplugin.Host{{Name: "w1", Address: "203.0.113.5"}, {Name: "home", Address: "198.51.100.9"}})
	if err != nil || len(hs) != 1 || hs[0].Name != "w1" || hs[0].ID != "42" {
		t.Fatalf("describe %+v %v", hs, err)
	}
	vs, err := c.EnsureVolume(ctx, kplugin.Volume{Class: "fake-block", ID: "u1/data", SizeBytes: 10 << 30, Region: "ca-central"})
	if err != nil || vs.Handle == "" {
		t.Fatalf("ensure volume %+v %v", vs, err)
	}
	at, err := c.AttachVolume(ctx, kplugin.Attachment{Class: "fake-block", Handle: vs.Handle, Host: hs[0]})
	if err != nil || at.Device == "" {
		t.Fatalf("attach %+v %v", at, err)
	}
	// A detach that takes a while: in progress first, done when asked again.
	err = c.DetachVolume(ctx, kplugin.Attachment{Class: "fake-block", Handle: vs.Handle, Host: hs[0]})
	if !errors.Is(err, kplugin.ErrInProgress) || err.Error() != "volume vol-1 still detaching: in progress" {
		t.Fatalf("first detach: %v", err)
	}
	if err := c.DetachVolume(ctx, kplugin.Attachment{Class: "fake-block", Handle: vs.Handle, Host: hs[0]}); err != nil {
		t.Fatalf("second detach: %v", err)
	}
	if err := c.DeleteVolume(ctx, kplugin.VolumeRef{Class: "fake-block", Handle: vs.Handle}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteVolume(ctx, kplugin.VolumeRef{Class: "fake-block", Handle: vs.Handle}); !errors.Is(err, kplugin.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	r := kplugin.Record{Provider: "fake-dns", Name: "app.example.com", Type: "A", Values: []string{"198.51.100.10"}, Owner: "kevaso:a"}
	if err := c.EnsureRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	r2 := r
	r2.Owner = "kevaso:b"
	if err := c.EnsureRecord(ctx, r2); !errors.Is(err, kplugin.ErrConflict) {
		t.Fatalf("someone else's record: %v", err)
	}
	st, err := c.EnsureLoadBalancer(ctx, kplugin.LoadBalancer{Class: "fake-lb", ID: "u1", Ports: []kplugin.Port{{Name: "web", Protocol: "TCP", Port: 80, NodePort: 30000}}, Backends: hs})
	if err != nil || st.Address == "" || len(st.SourceRanges) != 1 {
		t.Fatalf("lb %+v %v", st, err)
	}
}

func TestUnservedInterfaces(t *testing.T) {
	c := serve(t, infoOnly{})
	if _, err := c.EnsureVolume(context.Background(), kplugin.Volume{}); !errors.Is(err, kplugin.ErrUnsupported) {
		t.Fatalf("volumes on a plugin without them: %v", err)
	}
	if _, err := c.DescribeHosts(context.Background(), nil); !errors.Is(err, kplugin.ErrUnsupported) {
		t.Fatalf("hosts on a plugin without them: %v", err)
	}
}
