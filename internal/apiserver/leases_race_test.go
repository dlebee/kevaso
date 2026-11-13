package apiserver

import (
	"context"
	"math/rand/v2"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/leases"
	"kevaso.com/core/internal/store"
)

// A lease renewed at the very moment it runs out, while the sweep closes leases whose time is up,
// over and over (run with -race): a renewal that answered "open until U" is what's stored after
// both, never closed by the sweep behind its back; a renewal that lost the race says so (try
// again) and the sweep's close stands.
func TestLeaseRenewalRacesTheSweep(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	s, err := New(jittery{store.NewMemory(0)}, clk)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}); err != nil {
		t.Fatal(err)
	}
	si := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "d"}, Spec: v1.SiloSpec{
		Runtime: "docker", Container: &v1.ContainerSource{Image: "nginx:1.27"},
		Ports:   []v1.SiloPort{{Name: "rpc", Port: 8545}},
		Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "rpc", HostPort: []string{v1.NetworkExternal}, Lease: &v1.PortLease{Max: "1h"}}}}}}
	if err := c.Create(ctx, si); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Silo", "d", "rpc", si); err != nil {
		t.Fatal(err)
	}
	ask := leases.Ask{Port: "rpc", For: "1m", By: "ada"}
	if out := s.leaseAsk(ctx, si, ask, "user"); out.Err != nil || !out.Open {
		t.Fatalf("first open: %+v", out)
	}
	rounds := 200
	if testing.Short() {
		rounds = 30
	}
	renewedWon, sweepWon := 0, 0
	for i := 0; i < rounds; i++ {
		l, _, _ := s.getLease(ctx, "d", leases.Name("rpc", "rpc"))
		clk.Step(l.Status.Until.Sub(clk.Now())) // exactly when it runs out
		var out leases.Outcome
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); out = s.leaseAsk(ctx, si, ask, "user") }()
		go func() { defer wg.Done(); _ = s.SweepLeases(ctx) }()
		wg.Wait()
		got, _, err := s.getLease(ctx, "d", leases.Name("rpc", "rpc"))
		if err != nil {
			t.Fatal(err)
		}
		now := clk.Now()
		switch {
		case out.Err == nil && out.Open:
			renewedWon++
			if !got.IsOpen(si.UID, now) || !got.Status.Until.Equal(out.Until) {
				t.Fatalf("round %d: the renewal said open until %s; stored: %s until %v (%s)", i, out.Until, got.Status.Phase, got.Status.Until, got.Status.Reason)
			}
		case out.Err != nil:
			sweepWon++
			if got.IsOpen(si.UID, now) {
				t.Fatalf("round %d: the renewal failed (%v), yet the lease is open", i, out.Err)
			}
			// The asker tries again, as it's told to: it opens.
			if again := s.leaseAsk(ctx, si, ask, "user"); again.Err != nil || !again.Open {
				t.Fatalf("round %d: asking again: %+v", i, again)
			}
		default:
			t.Fatalf("round %d: %+v", i, out)
		}
	}
	t.Logf("renewal first %d times, sweep first %d", renewedWon, sweepWon)
}

// jittery delays reads a little, at random, so writers that read at once interleave every way.
type jittery struct{ store.Store }

func (j jittery) Get(ctx context.Context, k store.Key) (store.Object, error) {
	o, err := j.Store.Get(ctx, k)
	time.Sleep(time.Duration(rand.IntN(300)) * time.Microsecond)
	return o, err
}

func (j jittery) List(ctx context.Context, sel store.Selector) ([]store.Object, int64, error) {
	l, rev, err := j.Store.List(ctx, sel)
	time.Sleep(time.Duration(rand.IntN(300)) * time.Microsecond)
	return l, rev, err
}
