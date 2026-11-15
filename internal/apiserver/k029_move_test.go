package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/claims"
	"kevaso.com/core/internal/clock"
	siloctl "kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/store"
)

// K-029 (surface lane): kvo move puts a silo on a host, so it takes the same claims as the
// scheduler (siloctl.ClaimPorts) before its write, with the node ports the silo will have on the
// new host (scheduler.ServiceStatus there, not the old host's): a port another silo holds there
// makes the target not fit. Here the silo controller has claimed port 80 on hv1 for d and is about
// to write d's placement; c (port 80) is moved to hv1 in between. Today the move only reads the
// stored silos, where d isn't on hv1 yet, and both end up holding port 80 on hv1.
func TestK029AMoveTakesThePlacementsClaims(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	for _, n := range []string{"hv1", "hv2"} {
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: n},
			Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		must(c.Create(ctx, h))
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 4, Memory: "8Gi"}
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue}}
		must(c.UpdateStatus(ctx, h))
	}
	mk := func(name string) *v1.Silo {
		s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Ports:   []v1.SiloPort{{Name: "http", Port: 80}},
				Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", HostPort: []string{v1.NetworkInternal}}}}}}
		must(c.Create(ctx, s))
		return s
	}
	cs := mk("c")
	cs.Status.Host, cs.Status.Phase = "hv2", "Running"
	must(c.UpdateStatus(ctx, cs))
	d := mk("d")
	// The silo controller's step before its write of d's placement on hv1.
	held, err := siloctl.ClaimPorts(ctx, &claims.Claims{Store: st}, d, v1.SiloStatus{Host: "hv1"})
	if err != nil || held != nil {
		t.Fatalf("claiming for d: %v %+v", err, held)
	}
	var out v1.Silo
	err = c.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/d/silos/c/move", moves.Request{To: "hv1"}, &out)
	if err == nil {
		t.Fatalf("c moved onto hv1, where d's port 80 is claimed: %+v", out.Status)
	}
}

// K-029, next to it: a move that is accepted holds its port on the new host (so the scheduler's
// claim for another silo there is refused), and one that is refused leaves the silo where it was.
func TestK029AMoveHoldsItsPortAndARefusedMoveChangesNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	for _, n := range []string{"hv1", "hv2", "hv3"} {
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: n},
			Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		must(c.Create(ctx, h))
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 4, Memory: "8Gi"}
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue}}
		must(c.UpdateStatus(ctx, h))
	}
	mk := func(name, host string) *v1.Silo {
		s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Ports:   []v1.SiloPort{{Name: "http", Port: 80}},
				Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", HostPort: []string{v1.NetworkInternal}}}}}}
		must(c.Create(ctx, s))
		if host != "" {
			s.Status.Host, s.Status.Phase = host, "Running"
			must(c.UpdateStatus(ctx, s))
		}
		return s
	}
	_, d, e := mk("c", "hv2"), mk("d", ""), mk("e", "hv1")
	move := func(name, to string) error {
		var out v1.Silo
		return c.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/d/silos/"+name+"/move", moves.Request{To: to}, &out)
	}
	must(move("c", "hv3"))
	if held, err := siloctl.ClaimPorts(ctx, &claims.Claims{Store: st}, d, v1.SiloStatus{Host: "hv3"}); err != nil || held == nil || len(held.HostPorts) == 0 {
		t.Fatalf("after c moved to hv3, d's claim of port 80 there: %+v %v, want held", held, err)
	}
	if err := move("e", "hv3"); err == nil {
		t.Fatalf("e moved onto hv3, where c holds port 80")
	}
	must(c.Get(ctx, "Silo", "d", "e", e))
	if e.Status.Host != "hv1" || e.Status.MovingFrom != "" {
		t.Fatalf("a refused move changed e: %+v", e.Status)
	}
}

// K-029, the same shape: a raw PUT of silos/status that puts a silo on another host (an admin's,
// a tool's) takes the scheduler's claims there first (apiserver update, siloctl.ClaimPorts at the
// write's version), and is refused (422) when another silo holds its host port.
func TestK029ARawStatusWriteOntoAHeldHostPortIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	mk := func(name string) *v1.Silo {
		s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"},
				Ports:   []v1.SiloPort{{Name: "http", Port: 80}},
				Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", HostPort: []string{v1.NetworkInternal}}}}}}
		must(c.Create(ctx, s))
		return s
	}
	a, b := mk("a"), mk("b")
	if held, err := siloctl.ClaimPorts(ctx, &claims.Claims{Store: st}, a, v1.SiloStatus{Host: "hv1"}); err != nil || held != nil {
		t.Fatalf("claiming for a: %v %+v", err, held)
	}
	a.Status.Host = "hv1"
	must(c.UpdateStatus(ctx, a))
	b.Status.Host = "hv1"
	if err := c.UpdateStatus(ctx, b); err == nil {
		t.Fatalf("a status write put b on hv1, where a holds port 80")
	}
}
