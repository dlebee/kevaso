package worker

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/sdk/kri"
)

// stateFiles is a host with only files (the runtimes' state).
type stateFiles map[string]string

func (f stateFiles) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("no commands here")
}
func (f stateFiles) WriteFile(p string, b []byte, _ os.FileMode) error { f[p] = string(b); return nil }
func (f stateFiles) ReadFile(p string) ([]byte, error) {
	if b, ok := f[p]; ok {
		return []byte(b), nil
	}
	return nil, os.ErrNotExist
}
func (f stateFiles) RemoveAll(p string) error { delete(f, p); return nil }
func (f stateFiles) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range f {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func idOfSilo(s *v1.Silo) kri.ID { return kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID} }

func initSilo(name string) *v1.Silo {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev", UID: "uid-" + name}}
	s.Status.Host, s.Status.Phase = "hv1", "Creating" // placed here, init still running: no siloIP yet
	return s
}

// K-002: a silo whose init is still running (no status.siloIP yet) is on the bridge already. Its
// port is bound from the moment its runtime saved its address, which is before the tap or veth
// exists, and a port whose silo has no address anywhere yet is closed.
func TestAPortIsBoundToTheRuntimesAddressBeforeStatus(t *testing.T) {
	vm, ctr, none := initSilo("vm"), initSilo("ctr"), initSilo("none")
	vmN, ctrN := cloudhypervisor.NamesFor(idOfSilo(vm)), cloudhypervisor.NamesFor(idOfSilo(ctr))
	files := stateFiles{
		vmN.Dir + "/silo.json": `{"id":{"namespace":"dev","name":"vm","uid":"uid-vm"},"ip":"10.64.0.7","mac":"52:4B:01:02:03:04"}`,
		cloudhypervisor.ContainersDir + "/" + ctrN.Short + "/state.json": `{"id":{"namespace":"dev","name":"ctr","uid":"uid-ctr"},"ip":"10.64.0.8"}`,
		// Not its own directory: binds nothing.
		cloudhypervisor.SilosDir + "/elsewhere/silo.json": `{"id":{"namespace":"dev","name":"none","uid":"uid-none"},"ip":"10.64.0.9"}`,
	}
	view := WithBindings(NetworkView("hv1", nil, []*v1.Silo{vm, ctr, none}, nil, nil), LocalBindings(files))
	bs := kni.Bindings(view.Local)
	want := map[string]kni.Binding{
		vmN.Tap:  {Tap: vmN.Tap, IP: netip.MustParseAddr("10.64.0.7"), MAC: "52:4b:01:02:03:04"},
		ctrN.Tap: {Tap: ctrN.Tap, IP: netip.MustParseAddr("10.64.0.8")},
	}
	if len(bs) != len(want) {
		t.Fatalf("bindings %+v, want %+v", bs, want)
	}
	for _, b := range bs {
		if want[b.Tap] != b {
			t.Errorf("binding %+v, want %+v", b, want[b.Tap])
		}
	}
	rules := kni.Rules(view)
	for _, w := range []string{
		`iifname "` + vmN.Tap + `" ether saddr 52:4b:01:02:03:04 ip saddr 10.64.0.7 accept`,
		`iifname "` + ctrN.Tap + `" ip saddr 10.64.0.8 accept`,
		"type filter hook prerouting priority filter; policy drop;",
	} {
		if !strings.Contains(rules, w) {
			t.Errorf("missing %q in:\n%s", w, rules)
		}
	}
	if noneTap := cloudhypervisor.NamesFor(idOfSilo(none)).Tap; strings.Contains(rules, noneTap) {
		t.Errorf("a silo with no address bound its port:\n%s", rules)
	}
	// The runtime's address wins over a status that says otherwise.
	vm.Status.SiloIP = "10.64.0.99"
	view = WithBindings(NetworkView("hv1", nil, []*v1.Silo{vm}, nil, nil), LocalBindings(files))
	if bs := kni.Bindings(view.Local); len(bs) != 1 || bs[0].IP.String() != "10.64.0.7" {
		t.Errorf("status won over the runtime's state: %+v", bs)
	}
}

// The egress gate tells silos apart by the port the loaded rules bind an address to, never by
// status.siloIP alone: before any ruleset loads it knows no one, and a silo whose status claims
// another's address is still not taken for it.
func TestTheGateKnowsASiloOnlyByItsBoundPort(t *testing.T) {
	a, b := initSilo("a"), initSilo("b")
	a.Status.SiloIP, b.Status.SiloIP = "10.64.0.2", "10.64.0.2" // b's status lies
	silos := []*v1.Silo{b, a}
	e := &egress{hostName: "hv1", silos: func() []*v1.Silo { return silos }, bound: &loadedBindings{}}
	x := netip.MustParseAddr("10.64.0.2")
	if s, ok := e.local(x); ok {
		t.Fatalf("nothing loaded yet, but %s was taken for %s", x, s.Name)
	}
	e.bound.set([]kni.Binding{{Tap: cloudhypervisor.NamesFor(idOfSilo(a)).Tap, IP: x}})
	if s, ok := e.local(x); !ok || s.Name != "a" {
		t.Fatalf("%s: %v %v, want silo a (its bound port)", x, s, ok)
	}
	if _, ok := e.local(netip.MustParseAddr("10.64.0.3")); ok {
		t.Fatal("an unbound address was taken for a silo")
	}
}

// The DNS listener answers a silo with its own namespace's names: the namespace of the silo whose
// port the address is bound to, not of whichever silo's status claims it.
func TestDNSAskerIsTheSiloOnTheBoundPort(t *testing.T) {
	a, b := initSilo("a"), initSilo("b")
	b.Namespace = "other"
	a.Status.SiloIP, b.Status.SiloIP = "10.64.0.2", "10.64.0.2"
	silos := []*v1.Silo{b, a}
	l := &loadedBindings{}
	x := netip.MustParseAddr("10.64.0.2")
	if ns, ok := boundNamespace("hv1", silos, l, x); ok {
		t.Fatalf("nothing loaded, asker taken for namespace %s", ns)
	}
	l.set([]kni.Binding{{Tap: cloudhypervisor.NamesFor(idOfSilo(a)).Tap, IP: x}})
	if ns, ok := boundNamespace("hv1", silos, l, x); !ok || ns != "dev" {
		t.Fatalf("asker %q %v, want dev (silo a's port)", ns, ok)
	}
	if ns, ok := SiloNamespaces(silos)(x); ok && ns != "dev" {
		t.Logf("by status alone the asker would be %q", ns) // why the listener doesn't go by it
	}
}

func TestWatchBindingsPokesOnAChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n atomic.Int32
	cur := atomic.Pointer[map[string]Bound]{}
	m0 := map[string]Bound{}
	cur.Store(&m0)
	poked := make(chan struct{}, 4)
	go watchBindings(ctx, 5*time.Millisecond, func() map[string]Bound { n.Add(1); return *cur.Load() }, func() { poked <- struct{}{} })
	for n.Load() < 3 {
		time.Sleep(time.Millisecond)
	}
	select {
	case <-poked:
		t.Fatal("poked with nothing changed")
	default:
	}
	m1 := map[string]Bound{"kvt1": {IP: netip.MustParseAddr("10.64.0.2")}}
	cur.Store(&m1)
	select {
	case <-poked:
	case <-ctx.Done():
		t.Fatal("a new state file didn't poke")
	}
}
