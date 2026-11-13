package etcd

import (
	"context"
	"fmt"
	"net"
	"sort"

	clientv3 "go.etcd.io/etcd/client/v3"

	v1 "kevaso.com/core/api/v1"
)

// DefaultPeerPort is where members listen for each other.
const DefaultPeerPort = "2380"

// Desired is a host that should be an etcd member: every Host with the control-plane component,
// a light system node (stateOnly: store member only, no API server or controllers) included.
type Desired struct {
	Name      string
	PeerURL   string
	StateOnly bool
}

// DesiredMembers is the member list the Hosts ask for, sorted by name.
func DesiredMembers(hosts []v1.Host) []Desired {
	var out []Desired
	for _, h := range hosts {
		cp := h.Spec.Components.ControlPlane
		if cp == nil || h.Spec.Address == "" {
			continue
		}
		out = append(out, Desired{Name: h.Name, PeerURL: "https://" + net.JoinHostPort(h.Spec.Address, DefaultPeerPort), StateOnly: cp.StateOnly})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Member is a current etcd member as the decision needs it.
type Member struct {
	ID       uint64
	Name     string // empty until an added member first starts
	PeerURLs []string
	Learner  bool
	Healthy  bool // the caller's judgment, e.g. its Host is heartbeating
}

// Action is one membership change.
type Action string

const (
	None       Action = ""           // the members are what's desired
	Wait       Action = "Wait"       // a learner is catching up; ask again later
	Blocked    Action = "Blocked"    // no safe step (Reason says why)
	AddLearner Action = "AddLearner" // add Name at PeerURL as a learner (no vote until promoted)
	Promote    Action = "Promote"    // make learner ID a voter
	Remove     Action = "Remove"     // remove member ID
)

// Step is the one safe change to make next.
type Step struct {
	Action  Action
	ID      uint64
	Name    string
	PeerURL string
	Reason  string
}

// NextStep decides the one membership change to make now, from the desired and current members.
// One change at a time, each keeping a majority of healthy voters:
//
//  1. nothing changes without a healthy majority now (etcd couldn't commit it);
//  2. a learner no longer desired is removed (learners don't vote: always safe);
//  3. a desired learner is promoted once healthy (etcd also refuses until it caught up);
//  4. an unhealthy voter no longer desired is removed, if the rest keep a majority;
//  5. a desired host that isn't a member is added as a learner, one at a time;
//  6. a healthy voter no longer desired is removed, if the rest keep a majority, never the last.
//
// Adding before removing healthy members means a replacement joins before the old one leaves.
func NextStep(desired []Desired, current []Member) Step {
	want := map[string]Desired{}
	for _, d := range desired {
		want[d.Name] = d
	}
	match := func(m Member) (Desired, bool) {
		if d, ok := want[m.Name]; ok && m.Name != "" {
			return d, true
		}
		for _, d := range desired { // not started yet: known by its peer URL
			for _, u := range m.PeerURLs {
				if u == d.PeerURL {
					return d, true
				}
			}
		}
		return Desired{}, false
	}
	cur := append([]Member(nil), current...)
	sort.Slice(cur, func(i, j int) bool { return cur[i].Name < cur[j].Name || (cur[i].Name == cur[j].Name && cur[i].ID < cur[j].ID) })

	voters, healthy := 0, 0
	for _, m := range cur {
		if !m.Learner {
			voters++
			if m.Healthy {
				healthy++
			}
		}
	}
	if voters == 0 || !majority(healthy, voters) {
		return Step{Action: Blocked, Reason: fmt.Sprintf("only %d of %d voters are healthy: no majority to change membership with", healthy, voters)}
	}
	present := map[string]bool{}
	for _, m := range cur {
		if d, ok := match(m); ok {
			present[d.Name] = true
		}
	}
	// 2, 3: learners.
	for _, m := range cur {
		if !m.Learner {
			continue
		}
		d, ok := match(m)
		if !ok {
			return Step{Action: Remove, ID: m.ID, Name: m.Name, Reason: "learner not desired"}
		}
		if !m.Healthy {
			return Step{Action: Wait, ID: m.ID, Name: d.Name, Reason: "learner " + d.Name + " isn't up yet"}
		}
		return Step{Action: Promote, ID: m.ID, Name: d.Name, Reason: "learner " + d.Name + " is up"}
	}
	// 4: unhealthy voters that should go.
	for _, m := range cur {
		if _, ok := match(m); !ok && !m.Learner && !m.Healthy {
			if voters-1 >= 1 && majority(healthy, voters-1) {
				return Step{Action: Remove, ID: m.ID, Name: m.Name, Reason: "unhealthy voter not desired"}
			}
		}
	}
	// 5: missing members.
	for _, d := range desired {
		if !present[d.Name] {
			return Step{Action: AddLearner, Name: d.Name, PeerURL: d.PeerURL, Reason: "desired, not a member"}
		}
	}
	// 6: healthy voters that should go.
	for _, m := range cur {
		if _, ok := match(m); ok || m.Learner {
			continue
		}
		if voters-1 >= 1 && majority(healthy-boolInt(m.Healthy), voters-1) {
			return Step{Action: Remove, ID: m.ID, Name: m.Name, Reason: "voter not desired"}
		}
		return Step{Action: Blocked, ID: m.ID, Name: m.Name, Reason: fmt.Sprintf("removing %s would leave no healthy majority", m.Name)}
	}
	return Step{Action: None}
}

func majority(healthy, voters int) bool { return healthy > voters/2 }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Members reads the current members; healthy says which are (by name; a learner that hasn't
// started has no name and isn't).
func Members(ctx context.Context, cli *clientv3.Client, healthy func(name string) bool) ([]Member, error) {
	ml, err := cli.MemberList(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(ml.Members))
	for _, m := range ml.Members {
		out = append(out, Member{ID: m.ID, Name: m.Name, PeerURLs: m.PeerURLs, Learner: m.IsLearner, Healthy: m.Name != "" && healthy(m.Name)})
	}
	return out, nil
}

// Apply makes one step through cli.
func Apply(ctx context.Context, cli *clientv3.Client, s Step) error {
	var err error
	switch s.Action {
	case AddLearner:
		_, err = cli.MemberAddAsLearner(ctx, []string{s.PeerURL})
	case Promote:
		_, err = cli.MemberPromote(ctx, s.ID)
	case Remove:
		_, err = cli.MemberRemove(ctx, s.ID)
	}
	if err != nil {
		return fmt.Errorf("etcd %s %s: %w", s.Action, s.Name, err)
	}
	return nil
}

// Reconcile decides and makes the next membership step: what `kvoadm` will call while it joins a
// second and third system node (each call one step; call again until it returns None). After
// AddLearner, start the new member with Join and InitialCluster from Cluster.
func Reconcile(ctx context.Context, cli *clientv3.Client, desired []Desired, healthy func(name string) bool) (Step, error) {
	ms, err := Members(ctx, cli, healthy)
	if err != nil {
		return Step{}, err
	}
	s := NextStep(desired, ms)
	return s, Apply(ctx, cli, s)
}

// Cluster is the InitialCluster a joining member starts with: every current member's name (the
// new one's from desired, as it has none yet) and peer URL.
func Cluster(ctx context.Context, cli *clientv3.Client, desired []Desired) (map[string]string, error) {
	ms, err := Members(ctx, cli, func(string) bool { return false })
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, m := range ms {
		name := m.Name
		if name == "" {
			for _, d := range desired {
				for _, u := range m.PeerURLs {
					if u == d.PeerURL {
						name = d.Name
					}
				}
			}
		}
		if name != "" && len(m.PeerURLs) > 0 {
			out[name] = m.PeerURLs[0]
		}
	}
	return out, nil
}
