package apiserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/claims"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

func TestPlatformHostPortsAreRefusedAtAdmission(t *testing.T) {
	for _, n := range []int{22, 53, 2379, 2380, 6443, 51820, 51821, 15001} {
		errs := checkPorts(hostPortAs(8080, n, true), "s", false)
		if len(errs) == 0 || !strings.Contains(strings.Join(errs, "; "), "which a silo may not take") {
			t.Errorf("host port %d: %v", n, errs)
		}
	}
	for _, n := range []int{80, 443, 8080, 2222} {
		if errs := checkPorts(hostPortAs(8080, n, true), "s", false); len(errs) != 0 {
			t.Errorf("host port %d, which a silo may take: %v", n, errs)
		}
	}
	// The declared port is the host number when as is unset.
	declared := v1.SiloSpec{
		Ports:    []v1.SiloPort{{Name: "web", Port: 6443}},
		Services: onWorker(v1.NetworkExternal, v1.ServicePort{Port: "web"}),
	}
	if errs := checkPorts(declared, "s", false); len(errs) == 0 || !strings.Contains(strings.Join(errs, "; "), "the API") {
		t.Fatalf("a declared 6443 opened on the host: %v", errs)
	}
	if errs := checkPorts(hostPortAs(8080, 6443, false), "s", false); len(errs) != 0 {
		t.Fatalf("a load balancer on 6443 is not the host's listener: %v", errs)
	}
}

func hostPortAs(declared, as int, onHost bool) v1.SiloSpec {
	sv := v1.SiloService{Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "web", As: as}}}
	if !onHost {
		sv.Type, sv.LoadBalancer = v1.ServiceLoadBalancer, &v1.LoadBalancerSpec{Provider: "linode"}
	}
	return v1.SiloSpec{Ports: []v1.SiloPort{{Name: "web", Port: declared}}, Services: []v1.SiloService{sv}}
}

// onWorker is one HostPort service on the worker's address on network.
func onWorker(network string, ports ...v1.ServicePort) []v1.SiloService {
	return []v1.SiloService{{Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: network}, Ports: ports}}
}

func TestAPlacedSiloCannotTakeAHostPortAnotherSiloHolds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	c, done := srv.InProcess()
	defer done()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	mk := func(name string, ports []v1.SiloPort, svc []v1.ServicePort) *v1.Silo {
		t.Helper()
		spec := v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}, Ports: ports}
		if len(svc) > 0 {
			spec.Services = onWorker(v1.NetworkInternal, svc...)
		}
		s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"}, Spec: spec}
		must(c.Create(ctx, s))
		return s
	}
	get := func(name string) *v1.Silo {
		t.Helper()
		var s v1.Silo
		must(c.Get(ctx, "Silo", "d", name, &s))
		return &s
	}
	place := func(s *v1.Silo) {
		t.Helper()
		cur := get(s.Name)
		cur.Status.Host, cur.Status.Phase = "hv1", "Running"
		must(c.UpdateStatus(ctx, cur))
	}
	held := mk("c", []v1.SiloPort{{Name: "http", Port: 80}}, []v1.ServicePort{{Port: "http"}})
	place(held)
	a := mk("a", nil, nil)
	place(a)

	a = get("a")
	a.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 80}}
	a.Spec.Services = onWorker(v1.NetworkInternal, v1.ServicePort{Port: "http"})
	err = c.Update(ctx, a)
	if codeOf(err) != http.StatusConflict || !strings.Contains(err.Error(), "held by d/c") {
		t.Fatalf("taking c's port: %v, want 409 naming d/c", err)
	}
	if stored := get("a"); len(stored.Spec.Services) > 0 {
		t.Fatalf("the refused update was stored: %+v", stored.Spec.Services)
	}

	a = get("a")
	a.Spec.Resources.Memory = "2Gi"
	must(c.Update(ctx, a))

	a = get("a")
	a.Spec.Ports = []v1.SiloPort{{Name: "extra", Port: 8081}, {Name: "http", Port: 80}}
	a.Spec.Services = onWorker(v1.NetworkInternal,
		v1.ServicePort{Port: "extra"},
		v1.ServicePort{Port: "http"},
	)
	if err := c.Update(ctx, a); codeOf(err) != http.StatusConflict {
		t.Fatalf("adding a free port and a held one: %v, want 409", err)
	}
	b := mk("b", nil, nil)
	place(b)
	b = get("b")
	b.Spec.Ports = []v1.SiloPort{{Name: "extra", Port: 8081}}
	b.Spec.Services = onWorker(v1.NetworkInternal, v1.ServicePort{Port: "extra"})
	if err := c.Update(ctx, b); err != nil {
		t.Fatalf("8081 was still claimed after the refused update: %v", err)
	}
	f := mk("f", nil, nil)
	place(f)
	f = get("f")
	f.Spec.Ports = []v1.SiloPort{{Name: "extra", Port: 8081}}
	f.Spec.Services = onWorker(v1.NetworkInternal, v1.ServicePort{Port: "extra"})
	if err := c.Update(ctx, f); codeOf(err) != http.StatusConflict || !strings.Contains(err.Error(), "held by d/b") {
		t.Fatalf("taking b's port: %v, want 409 naming d/b", err)
	}

	mk("u", nil, nil)
	u := get("u")
	u.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 80}}
	u.Spec.Services = onWorker(v1.NetworkInternal, v1.ServicePort{Port: "http"})
	if err := c.Update(ctx, u); err != nil {
		t.Fatalf("an unplaced silo claims nothing at admission: %v", err)
	}
	a = get("a")
	a.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 80}}
	a.Spec.Services = onWorker(v1.NetworkInternal, v1.ServicePort{Port: "http"})
	if err := c.Update(ctx, a); codeOf(err) != http.StatusConflict || !strings.Contains(err.Error(), "held by d/c") {
		t.Fatalf("the unplaced silo took c's port: %v", err)
	}

	e := mk("e", []v1.SiloPort{{Name: "http", Port: 90}}, []v1.ServicePort{{Port: "http", As: 9090}})
	place(e)
	e = get("e")
	e.Spec.Services[0].Ports[0].As = 80
	if err := c.Update(ctx, e); codeOf(err) != http.StatusConflict || !strings.Contains(err.Error(), "held by d/c") {
		t.Fatalf("changing as onto c's port: %v", err)
	}
	if stored := get("e"); stored.Spec.Services[0].Ports[0].As != 9090 {
		t.Fatalf("the refused as was stored: %d", stored.Spec.Services[0].Ports[0].As)
	}
}

func TestAHostPortAHostListensOnIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	c, done := srv.InProcess()
	defer done()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	open := func(name string, as int) *v1.Silo {
		return &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"},
				Ports:    []v1.SiloPort{{Name: "web", Port: 8080}},
				Services: onWorker(v1.NetworkExternal, v1.ServicePort{Port: "web", As: as})}}
	}
	if err := c.Create(ctx, open("early", 2222)); err != nil {
		t.Fatalf("2222 before any host listens there: %v", err)
	}
	must(c.Create(ctx, &v1.Host{TypeMeta: tm("Host"),
		ObjectMeta: meta.ObjectMeta{Name: "hv", Annotations: map[string]string{v1.AnnotationSSH: "root@10.0.0.9:2222"}},
		Spec:       v1.HostSpec{InternalIP: "10.0.0.9", Network: v1.HostNetwork{ListenPort: 51822}, Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}))
	if err := c.Create(ctx, open("ssh", 2222)); codeOf(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "the SSH port") {
		t.Fatalf("SSH 2222: %v, want 422 naming the SSH port", err)
	}
	if err := c.Create(ctx, open("mesh", 51822)); codeOf(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "the mesh") {
		t.Fatalf("listen port 51822: %v, want 422 naming the mesh", err)
	}
	set := &v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "set", Namespace: "d"},
		Spec: v1.SiloSetSpec{Instances: 1, Template: v1.SiloTemplate{SiloSpec: open("set", 2222).Spec}}}
	if err := c.Create(ctx, set); codeOf(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "the SSH port") {
		t.Fatalf("SiloSet template: %v, want 422", err)
	}
	if err := c.Create(ctx, open("web", 443)); err != nil {
		t.Fatalf("443 stays available: %v", err)
	}
}

// A silo that already holds a host port keeps it when a second write of that silo, which still
// sees the port as new, does not commit. The release puts back only a port that write claimed.
func TestAConflictingUpdateKeepsAHostPortTheSiloAlreadyHolds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	srv, c, done := hostPortServer(t, st)
	defer done()
	held := placeHostPort(t, ctx, c, "a", 8080)
	stale := *held
	stale.Spec.Ports = nil
	stale.Spec.Services = nil
	rel, err := srv.claimAddedHostPorts(ctx, &stale, held, held.ResourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	if rel != nil {
		rel()
	}
	who, ok := (&claims.Claims{Store: st}).Who(ctx, "host-port.hv1", "internal-tcp-8080")
	if !ok || who.UID != held.UID {
		t.Fatalf("claim after the conflicting write: %+v present=%v", who, ok)
	}
	b := placeHostPort(t, ctx, c, "b", 0)
	b.Spec.Ports = []v1.SiloPort{{Name: "web", Port: 8080}}
	b.Spec.Services = onWorker(v1.NetworkInternal, v1.ServicePort{Port: "web"})
	if err := c.Update(ctx, b); codeOf(err) != http.StatusConflict || !strings.Contains(err.Error(), "held by d/a") {
		t.Fatalf("another silo taking the port: %v, want 409 naming d/a", err)
	}
}

// A write that claims a host port and then does not commit puts that port back, so the next silo
// can take it.
func TestARefusedHostPortUpdateReleasesThePortItClaimed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	srv, c, done := hostPortServer(t, st)
	defer done()
	cur := placeHostPort(t, ctx, c, "a", 0)
	next := *cur
	next.Spec.Ports = []v1.SiloPort{{Name: "web", Port: 8080}}
	next.Spec.Services = onWorker(v1.NetworkInternal, v1.ServicePort{Port: "web"})
	rel, err := srv.claimAddedHostPorts(ctx, cur, &next, cur.ResourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	if rel == nil {
		t.Fatal("the new port was not claimed")
	}
	rel()
	if who, ok := (&claims.Claims{Store: st}).Who(ctx, "host-port.hv1", "internal-tcp-8080"); ok {
		t.Fatalf("a refused update left the claim: %+v", who)
	}
	if err := c.Update(ctx, &next); err != nil {
		t.Fatalf("the port after the refused update: %v", err)
	}
}

func hostPortServer(t *testing.T, st store.Store) (*Server, *client.Client, func()) {
	t.Helper()
	srv, err := New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	c, done := srv.InProcess()
	return srv, c, done
}

// placeHostPort creates a silo on hv1. port 0 leaves it with no host port; any other number is
// opened on the host's internal address after placement, which is what claims it.
func placeHostPort(t *testing.T, ctx context.Context, c *client.Client, name string, port int) *v1.Silo {
	t.Helper()
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}); err != nil && !client.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Silo", "d", name, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Running"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Silo", "d", name, s); err != nil {
		t.Fatal(err)
	}
	if port == 0 {
		return s
	}
	s.Spec.Ports = []v1.SiloPort{{Name: "web", Port: port}}
	s.Spec.Services = onWorker(v1.NetworkInternal, v1.ServicePort{Port: "web"})
	if err := c.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Silo", "d", name, s); err != nil {
		t.Fatal(err)
	}
	return s
}

func codeOf(err error) int {
	var e *client.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}
