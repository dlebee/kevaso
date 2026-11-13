package upgrade

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func v(s string) Version {
	x, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return x
}

func TestParseCompare(t *testing.T) {
	if _, err := Parse("1.2"); err == nil {
		t.Fatal("parsed 1.2")
	}
	if v("v0.4.1").String() != "v0.4.1" || v("0.4.1-rc.1").String() != "v0.4.1-rc.1" {
		t.Fatal("round trip")
	}
	order := []string{"v0.3.9", "v0.4.0-rc.1", "v0.4.0", "v0.4.1", "v1.0.0"}
	for i := 1; i < len(order); i++ {
		if v(order[i-1]).Compare(v(order[i])) != -1 || v(order[i]).Compare(v(order[i-1])) != 1 {
			t.Fatalf("%s < %s", order[i-1], order[i])
		}
	}
}

func TestUpgradeAllowed(t *testing.T) {
	for _, c := range []struct {
		from, to string
		ok       bool
	}{
		{"v0.4.0", "v0.4.0", true},
		{"v0.4.0", "v0.4.3", true},
		{"v0.4.3", "v0.5.0", true},
		{"v0.4.0", "v0.6.0", false}, // skips a minor
		{"v0.5.0", "v0.4.9", false}, // downgrade
		{"v0.9.0", "v1.0.0", false}, // major
	} {
		if err := UpgradeAllowed(v(c.from), v(c.to)); (err == nil) != c.ok {
			t.Errorf("%s → %s: %v", c.from, c.to, err)
		}
	}
}

func TestSkewAllowed(t *testing.T) {
	vs := func(ss ...string) []Version {
		var out []Version
		for _, s := range ss {
			out = append(out, v(s))
		}
		return out
	}
	for _, c := range []struct {
		name          string
		system, agent []Version
		ok            bool
	}{
		{"mid-roll of system nodes", vs("v0.4.2", "v0.5.0", "v0.5.0"), vs("v0.4.2"), true},
		{"agents one minor behind", vs("v0.5.0", "v0.5.0"), vs("v0.4.0"), true},
		{"system nodes two minors apart", vs("v0.3.0", "v0.5.0"), nil, false},
		{"agent ahead of a system node", vs("v0.4.2", "v0.5.0"), vs("v0.5.0"), false},
		{"agent two minors behind", vs("v0.6.0"), vs("v0.4.0"), false},
	} {
		if err := SkewAllowed(c.system, c.agent); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestMakePlan(t *testing.T) {
	cluster := func() []Node {
		return []Node{
			{Name: "cp-b", System: true, Version: "v0.4.0", Ready: true, Leader: true},
			{Name: "cp-a", System: true, Version: "v0.4.0", Ready: true},
			{Name: "vps", System: true, StateOnly: true, Version: "v0.4.0", Ready: true},
			{Name: "w3", Worker: true, Version: "v0.4.0", Ready: true},
			{Name: "w1", Worker: true, Version: "v0.4.0", Ready: true},
			{Name: "w2", Worker: true, Version: "v0.4.0", Ready: true},
			{Name: "both", System: true, Worker: true, Version: "v0.4.1", Ready: true},
		}
	}
	p, err := MakePlan(cluster(), "v0.4.1", 2)
	if err != nil {
		t.Fatal(err)
	}
	got := [][]string{}
	for _, s := range p.Steps {
		got = append(got, s.Hosts)
	}
	want := [][]string{{"vps"}, {"cp-a"}, {"cp-b"}, {"w1", "w2"}, {"w3"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("steps %v, want %v (light node first, leader last of the system nodes, workers in batches of 2)", got, want)
	}
	if !reflect.DeepEqual(p.Current, []string{"both"}) {
		t.Fatalf("current %v", p.Current)
	}

	refusals := []struct {
		name   string
		edit   func([]Node) []Node
		target string
		why    string
	}{
		{"a system node down: one more loses the majority", func(n []Node) []Node { n[1].Ready = false; return n }, "v0.4.1", "majority"},
		{"skips a minor", func(n []Node) []Node { return n }, "v0.6.0", "skips a minor"},
		{"downgrade", func(n []Node) []Node { return n }, "v0.3.9", "downgrade"},
		{"no version reported", func(n []Node) []Node { n[4].Version = ""; return n }, "v0.4.1", "no version"},
		{"two system nodes, no third vote", func(n []Node) []Node { return append(n[:1:1], n[1]) }, "v0.4.1", "third vote"},
		{"already outside the skew rule", func(n []Node) []Node { n[3].Version = "v0.5.0"; return n }, "v0.5.0", "skew"},
	}
	for _, r := range refusals {
		if _, err := MakePlan(r.edit(cluster()), r.target, 2); err == nil || !strings.Contains(err.Error(), r.why) {
			t.Errorf("%s: %v (want %q)", r.name, err, r.why)
		}
	}
	// A five-node store with one down can still restart one at a time.
	five := []Node{{Name: "a", System: true, Version: "v0.4.0"}, {Name: "b", System: true, Version: "v0.4.0", Ready: true},
		{Name: "c", System: true, Version: "v0.4.0", Ready: true}, {Name: "d", System: true, Version: "v0.4.0", Ready: true},
		{Name: "e", System: true, Version: "v0.4.0", Ready: true}}
	if _, err := MakePlan(five, "v0.4.1", 1); err != nil {
		t.Fatal(err)
	}
	// One system node: allowed, with a note.
	one := []Node{{Name: "a", System: true, Worker: true, Version: "v0.4.0", Ready: true}}
	if p, err := MakePlan(one, "v0.4.1", 1); err != nil || len(p.Notes) != 1 {
		t.Fatalf("%v %v", p, err)
	}
}

// fakeCluster is hosts with versions; Install restarts one (it's down until Healthy sees it back).
type fakeCluster struct {
	mu       sync.Mutex
	version  map[string]Version
	down     map[string]bool
	system   map[string]bool
	log      []string
	maxDown  int
	failHost string
}

func (f *fakeCluster) Majority(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	voters, up := 0, 0
	for h := range f.system {
		voters++
		if !f.down[h] {
			up++
		}
	}
	if up-1 <= voters/2 {
		return errors.New("no room to restart one")
	}
	return nil
}

func (f *fakeCluster) Install(_ context.Context, h string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h == f.failHost {
		return errors.New("signature check failed on the host")
	}
	// Skew must hold at every moment: no worker newer than the oldest system node.
	var sys, agents []Version
	for n, ver := range f.version {
		if f.system[n] {
			sys = append(sys, ver)
		} else {
			agents = append(agents, ver)
		}
	}
	if err := SkewAllowed(sys, agents); err != nil {
		return err
	}
	f.down[h] = true
	n := 0
	for _, d := range f.down {
		if d {
			n++
		}
	}
	f.maxDown = max(f.maxDown, n)
	f.log = append(f.log, "install "+h)
	return nil
}

func (f *fakeCluster) Healthy(_ context.Context, h string, to Version) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version[h], f.down[h] = to, false
	return nil
}

func TestExecute(t *testing.T) {
	f := &fakeCluster{version: map[string]Version{}, down: map[string]bool{}, system: map[string]bool{"cp-1": true, "cp-2": true, "vps": true}}
	nodes := []Node{}
	for _, h := range []string{"cp-1", "cp-2", "vps", "w1", "w2", "w3"} {
		f.version[h] = v("v0.4.0")
		nodes = append(nodes, Node{Name: h, System: f.system[h], StateOnly: h == "vps", Worker: !f.system[h], Version: "v0.4.0", Ready: true, Leader: h == "cp-1"})
	}
	p, err := MakePlan(nodes, "v0.5.0", 2)
	if err != nil {
		t.Fatal(err)
	}
	var reports []string
	if err := Execute(context.Background(), p, f, func(s string) { reports = append(reports, s) }); err != nil {
		t.Fatal(err)
	}
	for h, ver := range f.version {
		if ver != v("v0.5.0") {
			t.Fatalf("%s at %s", h, ver)
		}
	}
	if f.log[0] != "install vps" || f.log[2] != "install cp-1" {
		t.Fatalf("order %v", f.log)
	}
	if len(reports) != 5 { // 3 system nodes, then workers 2 + 1
		t.Fatalf("reports %v", reports)
	}

	// A host that refuses the binary stops the roll there, and says what's left.
	f2 := &fakeCluster{version: map[string]Version{}, down: map[string]bool{}, system: map[string]bool{"cp-1": true, "cp-2": true, "vps": true}, failHost: "cp-2"}
	for h := range f.version {
		f2.version[h] = v("v0.4.0")
	}
	err = Execute(context.Background(), p, f2, nil)
	if err == nil || !strings.Contains(err.Error(), "cp-2") || !strings.Contains(err.Error(), "w1") {
		t.Fatalf("want a stop at cp-2 naming what's left: %v", err)
	}
	if f2.version["w1"] != v("v0.4.0") {
		t.Fatal("a worker was upgraded after a system node failed")
	}
}
