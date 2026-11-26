package scheduler

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

// stored is the cluster as a store holds it, read back the way a controller reads it.
type stored struct {
	t  *testing.T
	st store.Store
}

func openStore(t *testing.T) stored {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "store.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() }) // before the temp folder goes (cleanups run last first)
	return stored{t, st}
}

func (s stored) put(kind, ns, name string, obj any) {
	s.t.Helper()
	b, err := json.Marshal(obj)
	if err != nil {
		s.t.Fatal(err)
	}
	k := store.Key{Kind: kind, Namespace: ns, Name: name}
	if cur, err := s.st.Get(context.Background(), k); err == nil {
		_, err = s.st.Update(context.Background(), k, b, cur.Revision)
		if err != nil {
			s.t.Fatal(err)
		}
		return
	}
	if _, err := s.st.Create(context.Background(), k, b); err != nil {
		s.t.Fatal(err)
	}
}

func list[T any](s stored, kind string) []*T {
	s.t.Helper()
	objs, _, err := s.st.List(context.Background(), store.Selector{Kind: kind})
	if err != nil {
		s.t.Fatal(err)
	}
	var out []*T
	for _, o := range objs {
		x := new(T)
		if err := json.Unmarshal(o.Data, x); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, x)
	}
	return out
}

// env is what the silo controller hands the scheduler, from the store.
func (s stored) env() ([]*v1.Host, []*v1.Silo, Env) {
	hs := list[v1.Host](s, "Host")
	silos := list[v1.Silo](s, "Silo")
	var placedSilos []*v1.Silo
	for _, x := range silos {
		if x.Status.Host != "" {
			placedSilos = append(placedSilos, x)
		}
	}
	return hs, placedSilos, Env{Hosts: hs, IPs: list[v1.IP](s, "IP"), IPSets: list[v1.IPSet](s, "IPSet"),
		SiloSets: list[v1.SiloSet](s, "SiloSet"), Networking: nets}
}

func (s stored) silo(name string) *v1.Silo {
	for _, x := range list[v1.Silo](s, "Silo") {
		if x.Name == name {
			return x
		}
	}
	s.t.Fatalf("no silo %s", name)
	return nil
}

// A SiloSet's instances with own, through a real store: each waits for its member with the
// reason, goes ahead by itself once the member is reserved and held, is placed where the member
// can be, and can move only within its reach.
func TestOwnThroughTheStore(t *testing.T) {
	s := openStore(t)
	for _, h := range append(cluster(), host("lin4", ext("172.105.0.4"), provider("linode", "ca-central"))) {
		s.put("Host", "", h.Name, h)
	}
	set := &v1.SiloSet{}
	set.APIVersion, set.Kind, set.Name, set.Namespace = v1.APIVersion, "SiloSet", "edge", "dev"
	set.Spec.Instances, set.Spec.IPs = 3, "edge-ips"
	s.put("SiloSet", "dev", "edge", set)
	ipset := &v1.IPSet{Spec: v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "ca-central", Max: 2}}
	ipset.Name, ipset.Namespace = "edge-ips", "dev"
	s.put("IPSet", "dev", "edge-ips", ipset)
	for i := range 3 {
		in := web(v1.InstanceName("edge", i), hostPortOwn(), workerExternal())
		in.Labels = map[string]string{v1.LabelSiloSet: "edge"}
		s.put("Silo", "dev", in.Name, in)
	}

	schedule := func(name string) Decision {
		t.Helper()
		hs, placedSilos, env := s.env()
		d, err := ScheduleIn(s.silo(name), hs, placedSilos, env)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	for name, want := range map[string]string{
		"edge-0": "waiting for IPSet edge-ips to reserve member 0 (IP edge-ips-0)",
		"edge-1": "waiting for IPSet edge-ips to reserve member 1 (IP edge-ips-1)",
		"edge-2": "no free member in IPSet edge-ips: instance edge-2 takes member 2, and its max is 2",
	} {
		if d := schedule(name); d.Host != "" || d.Message() != want {
			t.Errorf("%s: %+v, want %q", name, d, want)
		}
	}

	// The IP controller reserves member 0 and binds it: edge-0 goes ahead by itself.
	e0 := s.silo("edge-0")
	m0 := providerIP("edge-ips-0", "linode", "ca-central", nil, func(x *v1.IP) {
		x.Labels = map[string]string{v1.LabelIPSet: "edge-ips", v1.LabelIPSetOrdinal: "0"}
	})
	s.put("IP", "dev", m0.Name, m0)
	if d := schedule("edge-0"); d.Host != "" || d.Message() != "waiting for IP edge-ips-0 (IPSet edge-ips, member 0) to be bound to it" {
		t.Fatalf("reserved, not bound: %+v", d)
	}
	boundTo(e0)(m0)
	s.put("IP", "dev", m0.Name, m0)
	d := schedule("edge-0")
	if d.Host != "lin3" && d.Host != "lin4" {
		t.Fatalf("bound: %+v", d)
	}
	e0.Status.Host = d.Host
	s.put("Silo", "dev", e0.Name, e0)

	// Placed: it moves within ca-central's Linodes only.
	hs, placedSilos, env := s.env()
	other := map[string]string{"lin3": "lin4", "lin4": "lin3"}[d.Host]
	m, err := CanMove(s.silo("edge-0"), hs, placedSilos, env)
	want := "can move: to " + other + " (within linode machines in ca-central: IP edge-ips-0 (IPSet edge-ips, member 0) is linode's, in ca-central)"
	if err != nil || m.String() != want {
		t.Fatalf("%v\n got %s\nwant %s", err, m, want)
	}
	for _, to := range hs {
		why, err := MoveTo(s.silo("edge-0"), to, hs, placedSilos, env)
		switch {
		case err != nil:
			t.Fatal(err)
		case to.Name == other && why != "":
			t.Errorf("to %s refused: %s", to.Name, why)
		case to.Name != other && to.Name != d.Host && !strings.Contains(why, "is linode's, in ca-central") && !strings.Contains(why, "no external IP"):
			t.Errorf("to %s: %q", to.Name, why)
		}
	}
}
