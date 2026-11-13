package etcd

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/pki"
)

func host(name, addr string, cp *v1.ControlPlaneSpec) v1.Host {
	return v1.Host{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: v1.HostSpec{InternalIP: addr, Components: v1.HostComponents{ControlPlane: cp}}}
}

func TestDesiredMembers(t *testing.T) {
	got := DesiredMembers([]v1.Host{
		host("w1", "10.0.0.9", nil), // a worker only
		host("cp2", "10.0.0.2", &v1.ControlPlaneSpec{}),
		host("light", "10.0.0.3", &v1.ControlPlaneSpec{StateOnly: true}),
		host("cp1", "10.0.0.1", &v1.ControlPlaneSpec{}),
	})
	want := []Desired{
		{Name: "cp1", PeerURL: "https://10.0.0.1:2380"},
		{Name: "cp2", PeerURL: "https://10.0.0.2:2380"},
		{Name: "light", PeerURL: "https://10.0.0.3:2380", StateOnly: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %+v, want %+v", got[i], want[i])
		}
	}
}

func d(name string) Desired { return Desired{Name: name, PeerURL: "https://" + name + ":2380"} }

func voter(id uint64, name string, healthy bool) Member {
	return Member{ID: id, Name: name, PeerURLs: []string{"https://" + name + ":2380"}, Healthy: healthy}
}

func TestNextStep(t *testing.T) {
	learner := func(id uint64, name string, healthy bool) Member {
		m := voter(id, name, healthy)
		m.Learner = true
		return m
	}
	unstarted := Member{ID: 9, PeerURLs: []string{"https://cp2:2380"}, Learner: true}
	tests := []struct {
		name    string
		desired []Desired
		current []Member
		want    Step
	}{
		{"one system node, as desired", []Desired{d("cp1")}, []Member{voter(1, "cp1", true)}, Step{Action: None}},
		{"grow to two: add a learner first", []Desired{d("cp1"), d("cp2")}, []Member{voter(1, "cp1", true)},
			Step{Action: AddLearner, Name: "cp2", PeerURL: "https://cp2:2380"}},
		{"the learner hasn't started: wait, add nothing else", []Desired{d("cp1"), d("cp2"), d("light")}, []Member{voter(1, "cp1", true), unstarted},
			Step{Action: Wait, ID: 9, Name: "cp2"}},
		{"the learner is up: promote it", []Desired{d("cp1"), d("cp2")}, []Member{voter(1, "cp1", true), learner(2, "cp2", true)},
			Step{Action: Promote, ID: 2, Name: "cp2"}},
		{"two system nodes and a light one: add the third vote", []Desired{d("cp1"), d("cp2"), d("light")},
			[]Member{voter(1, "cp1", true), voter(2, "cp2", true)}, Step{Action: AddLearner, Name: "light", PeerURL: "https://light:2380"}},
		{"three, as desired", []Desired{d("cp1"), d("cp2"), d("light")},
			[]Member{voter(1, "cp1", true), voter(2, "cp2", true), voter(3, "light", true)}, Step{Action: None}},
		{"two of two needed and one is down: no change", []Desired{d("cp1"), d("cp3")},
			[]Member{voter(1, "cp1", true), voter(2, "cp2", false)}, Step{Action: Blocked}},
		{"a dead voter is replaced: remove it first when that's safe", []Desired{d("cp1"), d("cp2"), d("cp4")},
			[]Member{voter(1, "cp1", true), voter(2, "cp2", true), voter(3, "cp3", false)}, Step{Action: Remove, ID: 3, Name: "cp3"}},
		{"a healthy voter leaves after its replacement joined", []Desired{d("cp1"), d("cp2"), d("cp4")},
			[]Member{voter(1, "cp1", true), voter(2, "cp2", true), voter(3, "cp3", true), voter(4, "cp4", true)}, Step{Action: Remove, ID: 3, Name: "cp3"}},
		{"shrink two to one", []Desired{d("cp1")}, []Member{voter(1, "cp1", true), voter(2, "cp2", true)}, Step{Action: Remove, ID: 2, Name: "cp2"}},
		{"never remove the last voter", []Desired{d("cp2")}, []Member{voter(1, "cp1", true)},
			Step{Action: AddLearner, Name: "cp2", PeerURL: "https://cp2:2380"}},
		{"the last voter, alone and undesired, stays", nil, []Member{voter(1, "cp1", true)}, Step{Action: Blocked, ID: 1, Name: "cp1"}},
		{"removing a healthy voter would leave one of three healthy", []Desired{d("cp1"), d("cp2")},
			[]Member{voter(1, "cp1", true), voter(2, "cp2", false), voter(3, "cp3", true)}, Step{Action: Blocked, ID: 3, Name: "cp3"}},
		{"a learner nobody wants goes", []Desired{d("cp1")}, []Member{voter(1, "cp1", true), learner(5, "old", true)}, Step{Action: Remove, ID: 5, Name: "old"}},
		{"no voter healthy", []Desired{d("cp1")}, []Member{voter(1, "cp1", false)}, Step{Action: Blocked}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NextStep(tc.desired, tc.current)
			got.Reason = ""
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Every step NextStep takes keeps a healthy majority, over every small cluster shape.
func TestNextStepKeepsMajority(t *testing.T) {
	names := []string{"a", "b", "c", "d"}
	for mask := 0; mask < 1<<8; mask++ { // which of 4 are members, which are healthy
		var cur []Member
		for i, n := range names {
			if mask&(1<<i) != 0 {
				cur = append(cur, voter(uint64(i+1), n, mask&(1<<(i+4)) != 0))
			}
		}
		for dm := 0; dm < 1<<4; dm++ {
			var des []Desired
			for i, n := range names {
				if dm&(1<<i) != 0 {
					des = append(des, d(n))
				}
			}
			s := NextStep(des, cur)
			if s.Action != Remove {
				continue
			}
			voters, healthy := 0, 0
			for _, m := range cur {
				if m.ID != s.ID {
					voters++
					healthy += boolInt(m.Healthy)
				}
			}
			if voters == 0 || !majority(healthy, voters) {
				t.Fatalf("members %+v, desired %+v: removing %d leaves %d of %d healthy", cur, des, s.ID, healthy, voters)
			}
		}
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

// The growth path on loopback: a member started alone without peers, restarted with a peer
// listener, grows to two members through Reconcile (learner, then voter), then shrinks back.
func TestReconcileGrowAndShrink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ca, _ := pki.NewCA("c", time.Now())
	dir1, dir2 := filepath.Join(t.TempDir(), "cp1"), filepath.Join(t.TempDir(), "cp2")
	cfg1 := Config{Name: "cp1", Dir: dir1, CA: ca, ClientListen: "127.0.0.1:0", UnsafeNoFsync: true}
	s1, err := Start(ctx, cfg1)
	if err != nil {
		t.Fatal(err)
	}
	s1.Close()
	cfg1.PeerListen = freePort(t)
	if s1, err = Start(ctx, cfg1); err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	cli, err := s1.Client()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()

	peer2 := freePort(t)
	desired := []Desired{{Name: "cp1", PeerURL: "https://" + cfg1.PeerListen}, {Name: "cp2", PeerURL: "https://" + peer2}}
	up := map[string]bool{"cp1": true}
	healthy := func(n string) bool { return up[n] }

	step, err := Reconcile(ctx, cli, desired, healthy)
	if err != nil || step.Action != AddLearner {
		t.Fatalf("first step %+v, %v", step, err)
	}
	cluster, err := Cluster(ctx, cli, desired)
	if err != nil || len(cluster) != 2 || cluster["cp1"] != desired[0].PeerURL {
		t.Fatalf("cluster %v, %v (cp1's peer URL must be the one it advertises now)", cluster, err)
	}
	s2, err := Start(ctx, Config{Name: "cp2", Dir: dir2, CA: ca, ClientListen: "127.0.0.1:0", PeerListen: peer2,
		Join: true, InitialCluster: cluster, UnsafeNoFsync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	up["cp2"] = true
	for {
		step, err = Reconcile(ctx, cli, desired, healthy)
		if err == nil && step.Action == None {
			break
		}
		if err != nil && !errors.Is(err, rpctypes.ErrMemberLearnerNotReady) {
			t.Fatalf("step %+v: %v", step, err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("never reached two voters")
		case <-time.After(100 * time.Millisecond):
		}
	}
	ms, _ := Members(ctx, cli, healthy)
	if len(ms) != 2 || ms[0].Learner || ms[1].Learner {
		t.Fatalf("members %+v", ms)
	}
	if _, err := cli.Put(ctx, "k", "two voters"); err != nil {
		t.Fatal(err)
	}

	// etcd's own check refuses a removal until the members have been connected a few seconds:
	// the caller asks again.
	for {
		step, err = Reconcile(ctx, cli, desired[:1], healthy)
		if step.Action != Remove || step.Name != "cp2" {
			t.Fatalf("shrink %+v, %v", step, err)
		}
		if err == nil {
			break
		}
		if !errors.Is(err, rpctypes.ErrUnhealthy) {
			t.Fatalf("shrink: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("removal never allowed")
		case <-time.After(250 * time.Millisecond):
		}
	}
	if ms, _ := Members(ctx, cli, healthy); len(ms) != 1 {
		t.Fatalf("after removal: %+v", ms)
	}
	if _, err := cli.Put(ctx, "k", "one again"); err != nil {
		t.Fatal(err)
	}
}

// A system node's Host being deleted (kvoadm host remove, held by FinalizerMember) asks for no
// member, so the member controller removes it before the Host goes.
func TestDesiredMembersSkipsHostsBeingDeleted(t *testing.T) {
	now := time.Now()
	mk := func(name string, deleting bool) v1.Host {
		h := v1.Host{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: v1.HostSpec{ExternalIP: "203.0.113.1",
			Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{}}}}
		if deleting {
			h.DeletionTimestamp, h.Finalizers = &now, []string{FinalizerMember}
		}
		return h
	}
	d := DesiredMembers([]v1.Host{mk("cp-1", false), mk("cp-2", true)})
	if len(d) != 1 || d[0].Name != "cp-1" {
		t.Fatalf("desired: %+v", d)
	}
}
