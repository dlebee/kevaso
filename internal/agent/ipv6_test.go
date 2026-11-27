package agent_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// The IPv6 effort, wave 2: a host with IPv6 for its silos gives a new silo's runtime its IPv6
// subnet and gateway, and writes the address the runtime gave it as status.siloIPv6. A host
// without (Subnet6 ""): neither.
func TestTheRuntimeGetsTheSilosIPv6(t *testing.T) {
	for _, c := range []struct {
		name, subnet6          string // what the worker says
		spec6, gateway6, silo6 string // what the runtime gets, and the status
	}{
		{"with IPv6", "fd00:aa:bb:2::/64", "fd00:aa:bb:2::/64", "fd00:aa:bb:2::1", "fd00:aa:bb:2::4"},
		{"IPv4 only", "", "", "", ""},
		{"not a /64", "fd00:aa:bb:2::/56", "", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
			ts := httptest.NewServer(srv)
			t.Cleanup(func() { cancel(); ts.Close() })
			cl := client.New(ts.URL)
			_ = cl.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
			h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"}, Spec: v1.HostSpec{InternalIP: "10.0.0.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
			if err := cl.Create(ctx, h); err != nil {
				t.Fatal(err)
			}
			h.Status.Network.SiloSubnetIPv6 = "fd00:aa:bb:2::/64"
			if err := cl.UpdateStatus(ctx, h); err != nil {
				t.Fatal(err)
			}
			rt := fake.New()
			a := &agent.Agent{Client: cl, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{},
				Subnet6: func() string { return c.subnet6 }}
			agent.RunForTest(t, ctx, a)
			e := &env{c: cl, rt: rt, ctx: ctx}
			e.place(t, "web", "hv1", nil)
			s := e.wait(t, "web", func(s *v1.Silo) bool { return meta.IsTrue(s.Status.Conditions, "Ready") })
			spec, ok := rt.Spec(kri.ID{Namespace: "dev", Name: "web", UID: s.UID})
			if !ok || spec.Subnet6 != c.spec6 || spec.Gateway6 != c.gateway6 {
				t.Fatalf("spec subnet6 %q gateway6 %q", spec.Subnet6, spec.Gateway6)
			}
			if s.Status.SiloIPv6 != c.silo6 {
				t.Fatalf("status.siloIPv6 %q, want %q", s.Status.SiloIPv6, c.silo6)
			}
		})
	}
}
