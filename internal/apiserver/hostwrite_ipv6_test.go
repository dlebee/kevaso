package apiserver

import (
	"context"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// The IPv6 effort: a host gives a silo an IPv6 address only inside the /64 the control plane
// assigned it; a host without one, or not in the store, gives none (there is no default IPv6
// network).
func TestAHostGivesSiloIPv6OnlyInItsSubnet(t *testing.T) {
	ctx := context.Background()
	s, err := New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	c, done := s.InProcess()
	defer done()
	for _, name := range []string{"hv2", "hv3"} {
		h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{InternalIP: "10.0.0." + name[2:], Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
		if err := c.Create(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	h := &v1.Host{}
	if err := c.Get(ctx, "Host", "", "hv2", h); err != nil {
		t.Fatal(err)
	}
	h.Status.Network.SiloSubnet, h.Status.Network.SiloSubnetIPv6 = "10.64.2.0/24", "fd12:3456:789a:2::/64"
	if err := c.UpdateStatus(ctx, h); err != nil {
		t.Fatal(err)
	}
	old := v1.SiloStatus{}
	for _, tc := range []struct {
		host, addr string
		ok         bool
	}{
		{"hv2", "fd12:3456:789a:2::7", true},
		{"hv2", "", true},
		{"hv2", "fd12:3456:789a:3::7", false}, // another host's /64
		{"hv2", "2001:db8::7", false},
		{"hv2", "10.64.2.7", false},             // not IPv6
		{"hv2", "::ffff:10.64.2.7", false},      // mapped
		{"hv3", "fd12:3456:789a:3::7", false},   // a host without a /64 gives none
		{"gone", "fd12:3456:789a:2::7", false},  // nor one not in the store
		{"hv2", "fd12:3456:789a:2::7%x", false}, // a zone
	} {
		err := s.siloIPv6InSubnet(ctx, old, v1.SiloStatus{SiloIPv6: tc.addr}, tc.host)
		if (err == nil) != tc.ok {
			t.Errorf("%s gives %q: %v, want ok %v", tc.host, tc.addr, err, tc.ok)
		}
	}
	// One it gave before stays its to keep (the check is on a change).
	if err := s.siloIPv6InSubnet(ctx, v1.SiloStatus{SiloIPv6: "2001:db8::7"}, v1.SiloStatus{SiloIPv6: "2001:db8::7"}, "hv3"); err != nil {
		t.Fatalf("an unchanged address: %v", err)
	}
}
