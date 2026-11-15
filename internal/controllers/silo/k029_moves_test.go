package silo_test

import (
	"context"
	"encoding/json"
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
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/internal/store"
)

type k029 struct {
	ctx context.Context
	t   *testing.T
	st  store.Store
	c   *client.Client
}

func newK029(t *testing.T) *k029 {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetClasses(k029Classes)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	x := &k029{ctx: ctx, t: t, st: st, c: client.New(ts.URL)}
	x.must(x.c.Create(ctx, &v1.Namespace{TypeMeta: tmK029("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "dev"}}))
	for _, n := range []string{"hv1", "hv2"} {
		h := dockerHost(n)
		x.must(x.c.Create(ctx, h))
		h.Status = dockerHost(n).Status
		x.must(x.c.UpdateStatus(ctx, h))
	}
	return x
}

func tmK029(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }

func k029Classes() map[string]scheduler.Class {
	return map[string]scheduler.Class{"nb": {Plugin: "nb", NodePorts: true}}
}

func dockerHost(n string) *v1.Host {
	h := readyHost(n)
	h.Spec.InternalIP = "10.0.0.1"
	h.Spec.Components.Worker.Labels = map[string]string{"name": n}
	h.Spec.Components.Worker.Runtimes = []v1.RuntimeSpec{{Name: "docker"}}
	h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
	return h
}

func (x *k029) must(err error) {
	x.t.Helper()
	if err != nil {
		x.t.Fatal(err)
	}
}

// silo makes a container silo pinned to host: a load-balanced one on a node-port class (bound
// to the namespace's shared IP), or one with host port 80 on the internal network.
func (x *k029) silo(name, host string, hostPort bool) *v1.Silo {
	s := newSilo(name)
	s.Spec.Runtime, s.Spec.Container = "docker", &v1.ContainerSource{Image: "app"}
	s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate // a container moves only as a fresh copy
	s.Spec.Resources = v1.Resources{CPU: 1, Memory: "1Gi"}
	s.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 80}}
	if hostPort {
		s.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", HostPort: []string{v1.NetworkInternal}}}}
	} else {
		s.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", LoadBalancer: true}}, LoadBalancer: &v1.LoadBalancerSpec{Class: "nb"}}
	}
	if host != "" {
		s.Spec.Placement.HostSelector = map[string]string{"name": host}
	}
	x.must(x.c.Create(x.ctx, s))
	return s
}

func (x *k029) bindIP(silos ...*v1.Silo) {
	ip := &v1.IP{TypeMeta: tmK029("IP"), ObjectMeta: meta.ObjectMeta{Name: v1.DefaultIPName("nb"), Namespace: "dev",
		Labels: map[string]string{v1.LabelDefaultIP: "nb"}}, Spec: v1.IPSpec{Class: "nb", Reclaim: v1.ReclaimDelete}}
	x.must(x.c.Create(x.ctx, ip))
	for _, s := range silos {
		ip.Status.BoundTo = append(ip.Status.BoundTo, v1.IPHolder{Holder: v1.HolderSiloPrefix + s.Name, UID: s.UID, Ports: []string{"http"}})
	}
	x.must(x.c.UpdateStatus(x.ctx, ip))
}

func (x *k029) ctl() *silo.Controller {
	return &silo.Controller{Client: x.c, Silos: frozen(x.ctx, x.t, x.c, "Silo"), Hosts: frozen(x.ctx, x.t, x.c, "Host"), IPs: frozen(x.ctx, x.t, x.c, "IP"),
		Clock: clock.Real{}, Classes: k029Classes, Claims: &claims.Claims{Store: x.st}}
}

func (x *k029) reconcile(c *silo.Controller, name string) {
	x.t.Helper()
	if _, err := c.Reconcile(x.ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: name}); err != nil {
		x.t.Fatal(err)
	}
}

func (x *k029) get(name string) *v1.Silo {
	x.t.Helper()
	var s v1.Silo
	x.must(x.c.Get(x.ctx, "Silo", "dev", name, &s))
	return &s
}

// move is kvo move --recreate (a container): the API server's move handler, as a person calls it.
func (x *k029) move(name, to string) {
	x.t.Helper()
	var s v1.Silo
	x.must(x.c.Call(x.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/"+name+"/move", moves.Request{To: to, Recreate: true}, &s))
}

// unpin lets a silo pinned by its selector be moved elsewhere (a spec change the scheduler sees).
func (x *k029) unpin(name string) {
	s := x.get(name)
	s.Spec.Placement.HostSelector = nil
	x.must(x.c.Update(x.ctx, s))
}

// K-029's remainder: a silo moved onto a host (kvo move) must hold its node ports and host
// ports there by the store, as the scheduler's placements do. Here b and c are moved from hv2 to
// hv1; a controller whose cache predates the move then places a (node port) and d (host port
// 80) on hv1. Before the fix nothing claimed b's node port or c's host port on hv1, so a got b's
// node port and d c's port 80 there. The moved silos' claims are taken by the silo controller
// the first time it sees them on their new host.
func TestK029AMovedSiloHoldsItsPortsOnItsNewHost(t *testing.T) {
	x := newK029(t)
	b, a := x.silo("b", "hv2", false), x.silo("a", "hv1", false)
	x.bindIP(a, b)
	x.silo("c", "hv2", true)
	x.silo("d", "hv1", true)
	place := x.ctl()
	x.reconcile(place, "b")
	x.reconcile(place, "c")
	stale := x.ctl() // a new leader's cache, listed before the moves below

	x.unpin("b")
	x.unpin("c")
	x.move("b", "hv1")
	x.move("c", "hv1")
	seen := x.ctl() // the controller sees the moved silos on hv1
	x.reconcile(seen, "b")
	x.reconcile(seen, "c")
	if b := x.get("b"); b.Status.Host != "hv1" || len(b.Status.Service.NodePorts) != 1 {
		t.Fatalf("b not on hv1 with a node port: %+v", b.Status)
	}

	x.reconcile(stale, "a")
	x.reconcile(stale, "d")
	ga, gb := x.get("a"), x.get("b")
	if ga.Status.Host == "hv1" && len(ga.Status.Service.NodePorts) == 1 && ga.Status.Service.NodePorts[0].NodePort == gb.Status.Service.NodePorts[0].NodePort {
		t.Errorf("a and the moved b both have node port %d on hv1", gb.Status.Service.NodePorts[0].NodePort)
	}
	if gd := x.get("d"); gd.Status.Host == "hv1" {
		t.Errorf("d and the moved c both hold port 80 on hv1's internal IP")
	}
}

// Drain unplaces a silo (kvoadm host drain): the controller places it, and claims as for any
// placement. Its ports on the drained host are let go once it has left (a claim whose holder is
// on another host is taken over), and not before: while it hands off from the drained host it
// still holds them there.
func TestK029ADrainedSiloClaimsWhereItLandsAndLetsGoWhereItLeft(t *testing.T) {
	x := newK029(t)
	x.silo("c", "", true)
	ctl := x.ctl()
	x.reconcile(ctl, "c")
	c := x.get("c")
	from := c.Status.Host
	to := map[string]string{"hv1": "hv2", "hv2": "hv1"}[from]
	// What kvoadm host drain writes (DrainStatus), through StartHandoff.
	h, err := x.c.StartHandoff(x.ctx, c, func(cur *v1.Silo) (v1.SiloStatus, error) {
		st := cur.Status
		st.Host, st.Phase, st.MovingFrom = "", "Pending", from
		return st, nil
	})
	x.must(err)
	var cur v1.Host
	x.must(x.c.Get(x.ctx, "Host", "", from, &cur))
	cur.Spec.Unschedulable = true
	x.must(x.c.Update(x.ctx, &cur))
	x.reconcile(x.ctl(), h.Name)
	if got := x.get("c"); got.Status.Host != to || got.Status.MovingFrom != from {
		t.Fatalf("drained c: host %q movingFrom %q", got.Status.Host, got.Status.MovingFrom)
	}
	// Its port 80 is c's on both hosts while it hands off.
	d := x.silo("d", from, true)
	x.must(x.c.Get(x.ctx, "Host", "", from, &cur))
	cur.Spec.Unschedulable = false
	x.must(x.c.Update(x.ctx, &cur))
	x.reconcile(x.ctl(), d.Name)
	if got := x.get("d"); got.Status.Host == from {
		t.Fatalf("d holds port 80 on %s while c still hands off from there", from)
	}
	// c lets go of the drained host: d may have port 80 there now.
	got := x.get("c")
	released, ok := moves.Released(got.Status, from)
	if !ok {
		t.Fatal("c can't be released")
	}
	got.Status = released
	x.must(x.c.UpdateStatus(x.ctx, got))
	x.reconcile(x.ctl(), d.Name)
	if got := x.get("d"); got.Status.Host != from {
		t.Fatalf("d not placed on %s once c let go: %+v", from, got.Status)
	}
}

// Two silos written onto hv1 with the same node port, and two with the same host port, by paths
// that didn't claim (a write from before claims existed, a move racing a placement). The first
// the controller sees keeps them; the second gets another node port, and for the host port,
// which can't be re-placed, the HostPorts condition says another silo holds it. It is set back to
// True once the other silo is gone.
func TestK029SilosPutOnAHostWithoutClaimingAreSortedOut(t *testing.T) {
	x := newK029(t)
	a, b := x.silo("a", "hv1", false), x.silo("b", "hv1", false)
	x.bindIP(a, b)
	x.silo("c", "hv1", true)
	x.silo("d", "hv1", true)
	ctl := x.ctl()
	x.reconcile(ctl, "a")
	np := x.get("a").Status.Service
	// Written in the store itself, as a restore or a store from before claims leaves them: the
	// API refuses such a status write now (it takes the claims, and a's are held).
	for _, name := range []string{"b", "c", "d"} {
		x.rawStatus(name, func(st *v1.SiloStatus) {
			st.Host, st.Phase = "hv1", "Running"
			if name == "b" {
				st.Service = np // a's node port, unclaimed
			}
		})
	}
	// a's claims came from ctl; a fresh controller (a new leader) sees all four placed.
	x.must(claimsReset(x))
	seen := x.ctl()
	for _, name := range []string{"a", "b", "c", "d"} {
		x.reconcile(seen, name)
	}
	ga, gb := x.get("a"), x.get("b")
	if ga.Status.Service.NodePorts[0].NodePort == gb.Status.Service.NodePorts[0].NodePort {
		t.Fatalf("a and b both keep node port %d on hv1", ga.Status.Service.NodePorts[0].NodePort)
	}
	if c := meta.FindCondition(x.get("c").Status.Conditions, silo.CondHostPorts); c != nil {
		t.Fatalf("c, seen first, got %+v", c)
	}
	gd := x.get("d")
	cond := meta.FindCondition(gd.Status.Conditions, silo.CondHostPorts)
	if gd.Status.Host != "hv1" || cond == nil || cond.Status != meta.ConditionFalse || cond.Reason != "HeldByAnother" {
		t.Fatalf("d: host %q, HostPorts %+v", gd.Status.Host, cond)
	}
	// Seen again: nothing new to write.
	x.reconcile(x.ctl(), "d")
	if again := x.get("d"); again.ResourceVersion != gd.ResourceVersion {
		t.Fatalf("d written again with nothing changed: %+v", meta.FindCondition(again.Status.Conditions, silo.CondHostPorts))
	}
	// c goes: d holds its port 80 now.
	x.must(x.c.Delete(x.ctx, "Silo", "dev", "c"))
	x.reconcile(x.ctl(), "d")
	if cond := meta.FindCondition(x.get("d").Status.Conditions, silo.CondHostPorts); cond == nil || cond.Status != meta.ConditionTrue {
		t.Fatalf("d once c is gone: %+v", cond)
	}
}

// claimsReset forgets every claim, as a store from before claims existed.
func claimsReset(x *k029) error {
	objs, _, err := x.st.List(x.ctx, store.Selector{Kind: claims.Kind})
	if err != nil {
		return err
	}
	for _, o := range objs {
		if _, err := x.st.Delete(x.ctx, o.Key, o.Revision); err != nil {
			return err
		}
	}
	return nil
}

// rawStatus changes a silo's status in the store itself, past the API and its checks.
func (x *k029) rawStatus(name string, f func(*v1.SiloStatus)) {
	x.t.Helper()
	k := store.Key{Kind: "Silo", Namespace: "dev", Name: name}
	o, err := x.st.Get(x.ctx, k)
	x.must(err)
	var s v1.Silo
	x.must(json.Unmarshal(o.Data, &s))
	f(&s.Status)
	b, err := json.Marshal(&s)
	x.must(err)
	_, err = x.st.Update(x.ctx, k, b, o.Revision)
	x.must(err)
}
