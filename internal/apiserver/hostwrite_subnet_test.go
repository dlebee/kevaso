package apiserver

import (
	"context"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// A missing host has no subnet, so it may use only the default network. An address in another
// host's subnet is refused. The status write of a removed host never reaches this check (its
// certificate is refused first); the check itself still fails closed.
func TestAMissingHostRefusesASiloAddress(t *testing.T) {
	ctx := context.Background()
	s, err := New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	c, done := s.InProcess()
	defer done()
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv2"},
		Spec: v1.HostSpec{ExternalIP: "203.0.113.10", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
	if err := c.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Host", "", "hv2", h); err != nil {
		t.Fatal(err)
	}
	h.Status.Network.SiloSubnet = "10.64.3.0/24"
	if err := c.UpdateStatus(ctx, h); err != nil {
		t.Fatal(err)
	}
	old := v1.SiloStatus{}
	if err := s.siloIPInSubnet(ctx, old, v1.SiloStatus{SiloIP: "10.64.3.7"}, "hv2"); err != nil {
		t.Fatalf("an address in the host's subnet: %v", err)
	}
	if err := s.siloIPInSubnet(ctx, old, v1.SiloStatus{SiloIP: "10.64.0.7"}, "gone"); err != nil {
		t.Fatalf("the default network for a host that is not in the store: %v", err)
	}
	if err := s.siloIPInSubnet(ctx, old, v1.SiloStatus{SiloIP: "10.64.3.7"}, "gone"); err == nil {
		t.Fatal("an address outside the default network for a host that is not in the store was kept")
	}
}
