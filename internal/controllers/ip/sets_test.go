package ip_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	ipctl "kevaso.com/core/internal/controllers/ip"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// setEnv runs the IP and IPSet controllers in an engine over an API server in memory, with the
// fake plugin (it reserves Provider IPs).
type setEnv struct {
	t    *testing.T
	ctx  context.Context
	c    *client.Client
	fake *kplugintest.Fake
}

func newSetEnv(t *testing.T) *setEnv {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done }) // the engine and informers stop before the server closes
	c := client.New(ts.URL)
	dir, _ := os.MkdirTemp("/tmp", "kvs")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fake := kplugintest.New()
	reg := &plugins.Registry{Dir: filepath.Join(dir, "plugins")}
	if err := reg.Add(ctx, fake); err != nil {
		t.Fatal(err)
	}
	e := engine.New(clock.Real{})
	infs := map[string]*informer.Informer{}
	for _, k := range []string{"IP", "IPSet", "Silo", "Service", "Host", "SiloSet"} {
		inf := informer.New(c, k)
		kind := k
		inf.AddHandler(func(key informer.Key) { e.Changed(engine.Key{Kind: kind, Namespace: key.Namespace, Name: key.Name}) })
		infs[k] = inf
		go inf.Run(ctx)
	}
	e.Register(&ipctl.Controller{Client: c, IPs: infs["IP"], Silos: infs["Silo"], Services: infs["Service"], Hosts: infs["Host"],
		SiloSets: infs["SiloSet"], IPSets: infs["IPSet"], Plugins: reg}, engine.Options{Workers: 1})
	e.Register(&ipctl.Sets{Client: c, IPSets: infs["IPSet"], IPs: infs["IP"], Silos: infs["Silo"], SiloSets: infs["SiloSet"]}, engine.Options{Workers: 1})
	go func() { e.Run(ctx); close(done) }()
	s := &setEnv{t: t, ctx: ctx, c: c, fake: fake}
	s.must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	return s
}

func (e *setEnv) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *setEnv) eventually(what string, cond func() (bool, string)) {
	e.t.Helper()
	last := ""
	for e.ctx.Err() == nil {
		ok, s := cond()
		if ok {
			return
		}
		last = s
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("%s: never happened; last: %s", what, last)
}

func (e *setEnv) ip(name string) (*v1.IP, bool) {
	var x v1.IP
	err := e.c.Get(e.ctx, "IP", "d", name, &x)
	if client.IsNotFound(err) {
		return nil, false
	}
	e.must(err)
	return &x, true
}

func (e *setEnv) set(name string) *v1.IPSet {
	var x v1.IPSet
	e.must(e.c.Get(e.ctx, "IPSet", "d", name, &x))
	return &x
}

var ownTemplate = v1.SiloTemplate{SiloSpec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
	Ports:    []v1.SiloPort{{Name: "smtp", Port: 25}},
	Services: []v1.SiloService{{Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Own: true}, Ports: []v1.ServicePort{{Port: "smtp"}}}}}}

// siloSet makes a SiloSet of n instances on IPSet ips, and its instances (as its controller would).
func (e *setEnv) siloSet(name, ips string, n int) *v1.SiloSet {
	e.t.Helper()
	ss := &v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
		Spec: v1.SiloSetSpec{Instances: n, IPs: ips, Template: ownTemplate}}
	e.must(e.c.Create(e.ctx, ss))
	for i := range n {
		e.instance(ss, i)
	}
	return ss
}

func (e *setEnv) instance(ss *v1.SiloSet, i int) {
	e.t.Helper()
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: v1.InstanceName(ss.Name, i), Namespace: "d",
		Labels:          map[string]string{v1.LabelSiloSet: ss.Name},
		OwnerReferences: []meta.OwnerReference{{APIVersion: v1.APIVersion, Kind: "SiloSet", Name: ss.Name, UID: ss.UID, Controller: true}}},
		Spec: ss.Spec.Template.SiloSpec}
	e.must(e.c.Create(e.ctx, s))
}

// A Dynamic set reserves Provider IPs (SET-0, SET-1, …) as its SiloSets' instances need them,
// up to max; each instance holds its own member by ordinal; scaled in, the members are kept;
// more instances than max wait, and the set says so.
func TestDynamicIPSetReservesPerOrdinal(t *testing.T) {
	e := newSetEnv(t)
	e.must(e.c.Create(e.ctx, &v1.IPSet{TypeMeta: tm("IPSet"), ObjectMeta: meta.ObjectMeta{Name: "edge", Namespace: "d"},
		Spec: v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "fake", Region: "ca-central", Max: 3}}))
	ss := e.siloSet("mx", "edge", 2)
	for i := range 2 {
		name := v1.DynamicMemberName("edge", i)
		e.eventually(name+" reserved and held by its instance", func() (bool, string) {
			x, ok := e.ip(name)
			if !ok {
				return false, "no IP " + name
			}
			return x.Status.Address != "" && x.Status.Holder != nil && x.Status.Holder.Holder == "silo/mx-"+strconv.Itoa(i),
				fmt.Sprintf("%+v labels %v", x.Status, x.Labels)
		})
	}
	if _, ok := e.ip("edge-2"); ok {
		t.Error("edge-2 made before an instance needs it")
	}
	e.eventually("the set lists its members", func() (bool, string) {
		st := e.set("edge").Status
		return len(st.Members) == 2 && st.Members[1].UsedBy == "silo/mx-1" && st.Members[1].Address != "", fmt.Sprintf("%+v", st.Members)
	})

	// Four instances wanted, max 3: the third member is made, the set says it's short.
	e.must(e.c.Get(e.ctx, "SiloSet", "d", "mx", ss))
	ss.Spec.Instances = 4
	e.must(e.c.Update(e.ctx, ss))
	e.eventually("edge-2 made, the set short", func() (bool, string) {
		_, ok := e.ip("edge-2")
		short := meta.FindCondition(e.set("edge").Status.Conditions, "Short")
		return ok && short != nil && short.Status == meta.ConditionTrue, fmt.Sprint(ok, short)
	})

	// Scaled in to one: every member is kept, the same address for the same ordinal later.
	before, _ := e.ip("edge-1")
	e.must(e.c.Get(e.ctx, "SiloSet", "d", "mx", ss))
	ss.Spec.Instances = 1
	e.must(e.c.Update(e.ctx, ss))
	e.must(e.c.Delete(e.ctx, "Silo", "d", "mx-1"))
	e.eventually("edge-1 let go, kept", func() (bool, string) {
		x, ok := e.ip("edge-1")
		return ok && x.Status.Holder == nil && x.Status.Address == before.Status.Address, fmt.Sprint(ok)
	})
	if _, ok := e.ip("edge-2"); !ok {
		t.Error("edge-2 went when the set scaled in: members are kept per ordinal")
	}
}

// A Static set: an ip member is that IP; a hostAddress member is an IP of type Host the set
// makes (SET-i). Deleting the set deletes what it made, once no instance holds it.
func TestStaticIPSetMembersAndDelete(t *testing.T) {
	e := newSetEnv(t)
	h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: "metal-1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.5", Addresses: []v1.HostAddress{{Name: "mail-b", Kind: v1.NetworkExternal, Address: "203.0.113.22"}},
			Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
	e.must(e.c.Create(e.ctx, h))
	e.must(e.c.Create(e.ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "a", Namespace: "d"},
		Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "fake", Region: "ca-central"}}))
	e.must(e.c.Create(e.ctx, &v1.IPSet{TypeMeta: tm("IPSet"), ObjectMeta: meta.ObjectMeta{Name: "mail", Namespace: "d"},
		Spec: v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{{IP: "a"}, {HostAddress: "mail-b"}}}}))
	e.siloSet("mx", "mail", 2)
	e.eventually("both members held by their instances", func() (bool, string) {
		a, _ := e.ip("a")
		b, ok := e.ip("mail-1")
		if !ok {
			return false, "no mail-1"
		}
		return a.Status.Holds(e.uid("mx-0")) && b.Status.Holds(e.uid("mx-1")) && b.Status.Address == "203.0.113.22" && b.Spec.Type == v1.IPTypeHost,
			fmt.Sprintf("a %+v; mail-1 %+v", a.Status, b.Status)
	})

	// Deleting the set while an instance holds its member: refused per IP, retried, the set stays.
	e.must(e.c.Delete(e.ctx, "IPSet", "d", "mail"))
	e.eventually("the set says what holds it", func() (bool, string) {
		r := meta.FindCondition(e.set("mail").Status.Conditions, "Ready")
		return r != nil && r.Reason == "Deleting", fmt.Sprint(r)
	})
	e.must(e.c.Delete(e.ctx, "Silo", "d", "mx-1"))
	e.eventually("the set gone with what it made; ip a kept", func() (bool, string) {
		var x v1.IPSet
		_, made := e.ip("mail-1")
		_, kept := e.ip("a")
		return client.IsNotFound(e.c.Get(e.ctx, "IPSet", "d", "mail", &x)) && !made && kept, fmt.Sprint(made, kept)
	})
}

func (e *setEnv) uid(silo string) string {
	var s v1.Silo
	if e.c.Get(e.ctx, "Silo", "d", silo, &s) != nil {
		return ""
	}
	return s.UID
}
