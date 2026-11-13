package controlplane

// More than one system node (design §3, §4.1; ADR 0006):
//
//   - Joining: a new system node starts with Config.Join. It makes a one-time key, presents its join
//     token (role system-node) and the key's public half to an existing control plane at
//     /join/system-node, which adds it to etcd as a learner and answers with the member list and
//     the cluster's identity (the CA, and the master key unless the node is state-only) sealed to
//     that key. The node writes the files, starts its member as a learner, and waits.
//   - The leader's member controller promotes the learner once etcd agrees it has caught up, and
//     removes members whose Host no longer asks for one, one step at a time, never losing the
//     healthy majority (etcd.NextStep), with health from the Hosts' heartbeats (etcd.Judge).
//   - Every system node serves the API; the controllers and the scheduler run only on the one that
//     holds the lease (internal/leader).
//   - A light node (StateOnly) runs its etcd member and nothing else, and heartbeats its Host by
//     writing it into the store directly (it has no API server to go through).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/etcd"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/leader"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/internal/version"
)

// JoinConfig is a system node joining an existing cluster, on its first start.
type JoinConfig struct {
	Servers   []string // control planes to ask (any one that answers will do)
	CA        []byte   // the cluster CA (pinned), PEM
	TokenFile string   // the one-time join token (role system-node); removed once used
	Token     string   // or the token itself (tests)
}

// selfReport is what this node says about its control plane in its Host's status.
type selfReport struct {
	apiURL  string
	store   string
	peerURL func() string
}

// joinState is the answer to a join, kept until the member has started from it: a restart in
// between uses it again (the token is spent).
const joinStateFile = "join.json"

// identity is the bundle a join hands over: data-dir-relative path → contents.
type identity struct {
	Files map[string][]byte `json:"files"`
}

// prepareJoin runs the join on a first start: afterwards the data dir has the cluster's identity
// and cfg.Etcd says which members to start with. A node that has started its member before (its
// etcd data exists) restarts from that and asks nothing.
func prepareJoin(ctx context.Context, cfg *Config) error {
	if cfg.Join == nil {
		return nil
	}
	etcdDir := filepath.Join(cfg.DataDir, "etcd")
	if _, err := os.Stat(filepath.Join(etcdDir, "data", "member")); err == nil {
		return nil
	}
	statePath := filepath.Join(etcdDir, joinStateFile)
	var resp client.SystemNodeJoinResponse
	if b, err := os.ReadFile(statePath); err == nil {
		if err := json.Unmarshal(b, &resp); err != nil {
			return fmt.Errorf("%s: %w", statePath, err)
		}
	} else {
		r, err := askToJoin(ctx, cfg)
		if err != nil {
			return err
		}
		resp = r
		if err := os.MkdirAll(etcdDir, 0o700); err != nil {
			return err
		}
		keep := resp
		keep.Bundle = nil // the identity is on disk now; don't keep a second copy
		b, _ := json.Marshal(keep)
		if err := os.WriteFile(statePath, b, 0o600); err != nil {
			return err
		}
	}
	if resp.Cluster != "" {
		cfg.ClusterName = resp.Cluster
	}
	cfg.Store = StoreEtcd
	cfg.Etcd.Join, cfg.Etcd.InitialCluster = true, resp.InitialCluster
	if u, err := url.Parse(resp.PeerURL); err == nil && u.Host != "" {
		cfg.Etcd.AdvertisePeer = u.Host
		if cfg.Etcd.PeerListen == "" {
			cfg.Etcd.PeerListen = u.Host
		}
	}
	return nil
}

// askToJoin presents the token and a fresh key's public half, and writes the identity it gets back.
func askToJoin(ctx context.Context, cfg *Config) (client.SystemNodeJoinResponse, error) {
	var resp client.SystemNodeJoinResponse
	tok := cfg.Join.Token
	if tok == "" {
		b, err := os.ReadFile(cfg.Join.TokenFile)
		if err != nil {
			return resp, fmt.Errorf("joining needs the one-time join token: %w", err)
		}
		tok = strings.TrimSpace(string(b))
	}
	rk := kms.NewRecoveryKey()
	pub, err := rk.Public()
	if err != nil {
		return resp, err
	}
	c, err := client.NewTLSEndpoints(cfg.Join.Servers, cfg.Join.CA, nil, nil)
	if err != nil {
		return resp, err
	}
	for attempt := 0; ; attempt++ {
		resp, err = c.JoinSystemNode(ctx, client.SystemNodeJoinRequest{Token: tok, Host: cfg.HostName, Recipient: pub})
		var ce *client.Error
		if err == nil {
			break
		}
		if errors.As(err, &ce) && (ce.Code == http.StatusUnauthorized || ce.Code == http.StatusForbidden || ce.Code == http.StatusBadRequest) {
			return resp, fmt.Errorf("join refused: %w", err)
		}
		cfg.Log("join: %v (trying again)", err) // busy, no majority yet, or nobody answering
		select {
		case <-ctx.Done():
			return resp, ctx.Err()
		case <-time.After(min(time.Duration(attempt+1)*500*time.Millisecond, 5*time.Second)):
		}
	}
	plain, err := kms.OpenWithRecovery(rk, resp.Bundle)
	if err != nil {
		return resp, fmt.Errorf("join: the identity doesn't open with this node's key: %w", err)
	}
	var id identity
	if err := json.Unmarshal(plain, &id); err != nil {
		return resp, err
	}
	for name, data := range id.Files {
		if !identityFile(name) {
			return resp, fmt.Errorf("join: unexpected file %q in the identity", name)
		}
		p := filepath.Join(cfg.DataDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return resp, err
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			return resp, err
		}
	}
	if cfg.Join.TokenFile != "" {
		_ = os.Remove(cfg.Join.TokenFile) // spent
	}
	cfg.Log("joined cluster %s: identity written, %d members to start with", resp.Cluster, len(resp.InitialCluster))
	return resp, nil
}

// identityFile: what a join may write (the CA's files; the master key).
func identityFile(name string) bool {
	if name == "kms/local.json" {
		return true
	}
	rest, ok := strings.CutPrefix(name, "pki/")
	return ok && rest != "" && !strings.ContainsAny(rest, `/\`) && rest != "." && rest != ".."
}

// joiner answers /join/system-node on this control plane.
type joiner struct {
	cfg   Config
	st    *cpStore
	clock func() time.Time
}

func refuse(code int, reason, f string, a ...any) error {
	return &client.Error{Code: code, Reason: reason, Message: fmt.Sprintf(f, a...)}
}

func (j *joiner) join(ctx context.Context, host string, recipient []byte) (client.SystemNodeJoinResponse, error) {
	var resp client.SystemNodeJoinResponse
	srv := j.st.etcd
	if srv == nil {
		return resp, refuse(http.StatusConflict, "StoreNotHA", "this cluster keeps its state in SQLite: switch the control plane to etcd first (kvoadm store migrate)")
	}
	if len(srv.Etcd.Peers) == 0 {
		return resp, refuse(http.StatusConflict, "NoPeerListener", "this control plane's etcd member has no peer listener: run kvoadm store migrate on it (it adds --etcd-peer-listen)")
	}
	hosts, err := storeHosts(ctx, j.st)
	if err != nil {
		return resp, err
	}
	var me *etcd.Desired
	desired := etcd.DesiredMembers(hosts)
	for i := range desired {
		if desired[i].Name == host {
			me = &desired[i]
		}
	}
	if me == nil {
		return resp, refuse(http.StatusConflict, "NotDeclared", "host %s isn't declared with the control-plane component (kvoadm host add declares it first)", host)
	}
	cli, err := srv.Client()
	if err != nil {
		return resp, err
	}
	defer func() { _ = cli.Close() }()
	ms, err := etcd.Members(ctx, cli, func(string) bool { return false })
	if err != nil {
		return resp, err
	}
	ms = etcd.Judge(ms, hosts, j.clock(), j.cfg.HostLease)
	present := false
	for _, m := range ms {
		named := m.Name == host
		byURL := false
		for _, u := range m.PeerURLs {
			byURL = byURL || u == me.PeerURL
		}
		if named && !m.Learner {
			return resp, refuse(http.StatusConflict, "AlreadyMember", "%s is already a voting member: remove it first (kvoadm host remove %s), then join it again", host, host)
		}
		present = present || named || byURL
	}
	if !present {
		step := etcd.NextStep(desired, ms)
		switch {
		case step.Action == etcd.AddLearner && step.Name == host:
			if err := etcd.Apply(ctx, cli, step); err != nil {
				return resp, refuse(http.StatusServiceUnavailable, "Busy", "%v", err)
			}
		case step.Action == etcd.Blocked:
			return resp, refuse(http.StatusConflict, "NoMajority", "%s", step.Reason)
		default:
			return resp, refuse(http.StatusConflict, "Busy", "another membership change comes first (%s %s: %s); one system node joins at a time", step.Action, step.Name, step.Reason)
		}
	}
	initial, err := etcd.Cluster(ctx, cli, desired)
	if err != nil {
		return resp, err
	}
	files := map[string][]byte{}
	pkiDir := filepath.Join(j.cfg.DataDir, "pki")
	es, err := os.ReadDir(pkiDir)
	if err != nil {
		return resp, err
	}
	for _, e := range es {
		if e.Type().IsRegular() {
			b, err := os.ReadFile(filepath.Join(pkiDir, e.Name()))
			if err != nil {
				return resp, err
			}
			files["pki/"+e.Name()] = b
		}
	}
	if !me.StateOnly { // a light node holds the store's sealed secrets, never the key to them (§3)
		b, err := os.ReadFile(filepath.Join(j.cfg.DataDir, "kms", "local.json"))
		if err != nil {
			return resp, fmt.Errorf("master key: %w", err)
		}
		files["kms/local.json"] = b
	}
	plain, _ := json.Marshal(identity{Files: files})
	sealed, err := kms.SealToRecovery(recipient, plain)
	if err != nil {
		return resp, refuse(http.StatusBadRequest, "BadRequest", "recipient: %v", err)
	}
	j.cfg.Log("system node %s joins as a learner (peer %s)", host, me.PeerURL)
	return client.SystemNodeJoinResponse{Cluster: j.cfg.ClusterName, PeerURL: me.PeerURL, InitialCluster: initial, Bundle: sealed}, nil
}

// storeHosts reads every Host from the store directly.
func storeHosts(ctx context.Context, st store.Store) ([]v1.Host, error) {
	objs, _, err := st.List(ctx, store.Selector{Kind: "Host"})
	if err != nil {
		return nil, err
	}
	out := make([]v1.Host, 0, len(objs))
	for _, o := range objs {
		obj, _, err := v1.Decode(o.Data)
		if err != nil {
			continue
		}
		if h, ok := obj.(*v1.Host); ok {
			out = append(out, *h)
		}
	}
	return out, nil
}

// runMembers is the leader's member controller: every interval, the one safe membership step
// (promote a learner that caught up; remove a member its Host no longer asks for), and the members
// and the leader shown on the Hosts. Learners are added only by a join (the machine is there).
func runMembers(ctx context.Context, c *client.Client, st *cpStore, cfg Config, every time.Duration) {
	srv := st.etcd
	cli, err := srv.Client()
	if err != nil {
		cfg.Log("member controller: %v", err)
		return
	}
	defer func() { _ = cli.Close() }()
	lastWhy := ""
	for {
		why := memberRound(ctx, c, cli, st, cfg)
		if why != lastWhy && why != "" && ctx.Err() == nil {
			cfg.Log("member controller: %s", why)
		}
		lastWhy = why
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func memberRound(ctx context.Context, c *client.Client, cli *clientv3.Client, st *cpStore, cfg Config) string {
	hosts, err := storeHosts(ctx, st)
	if err != nil {
		return err.Error()
	}
	ms, err := etcd.Members(ctx, cli, func(string) bool { return false })
	if err != nil {
		return err.Error()
	}
	ms = etcd.Judge(ms, hosts, cfg.Clock.Now(), cfg.HostLease)
	step := etcd.NextStep(etcd.DesiredMembers(hosts), ms)
	why := ""
	switch step.Action {
	case etcd.Promote, etcd.Remove:
		if err := etcd.Apply(ctx, cli, step); err != nil {
			why = fmt.Sprintf("%s %s: %v", step.Action, step.Name, err) // a learner not caught up yet: next round
		} else {
			cfg.Log("member controller: %s %s (%s)", step.Action, step.Name, step.Reason)
		}
	case etcd.Blocked, etcd.Wait:
		why = step.Reason
	}
	showMembers(ctx, c, hosts, ms, cfg.HostName, cfg)
	return why
}

// showMembers writes each system node's membership and who leads into its Host's status.
func showMembers(ctx context.Context, c *client.Client, hosts []v1.Host, ms []etcd.Member, leaderName string, cfg Config) {
	role := map[string]string{}
	for _, m := range ms {
		if m.Name != "" {
			role[m.Name] = map[bool]string{true: "learner", false: "voter"}[m.Learner]
		}
	}
	for _, h := range hosts {
		if h.Spec.Components.ControlPlane == nil && h.Status.ControlPlane == nil {
			continue
		}
		cur := v1.ControlPlaneStatus{}
		if h.Status.ControlPlane != nil {
			cur = *h.Status.ControlPlane
		}
		want := cur
		want.Member, want.Leader = role[h.Name], h.Name == leaderName
		if want == cur {
			continue
		}
		for attempt := 0; attempt < 3; attempt++ {
			var fresh v1.Host
			if err := c.Get(ctx, "Host", "", h.Name, &fresh); err != nil {
				break
			}
			cp := v1.ControlPlaneStatus{}
			if fresh.Status.ControlPlane != nil {
				cp = *fresh.Status.ControlPlane
			}
			cp.Member, cp.Leader = want.Member, want.Leader
			fresh.Status.ControlPlane = &cp
			if err := c.UpdateStatus(ctx, &fresh); err == nil || !client.IsConflict(err) {
				if err != nil && ctx.Err() == nil {
					cfg.Log("member status %s: %v", h.Name, err)
				}
				break
			}
		}
	}
}

// runLeader takes part in the controllers' election; lead runs while this node holds the lease.
func runLeader(ctx context.Context, st store.Store, cfg Config, lead func(ctx context.Context)) {
	e := &leader.Elector{Store: st, Key: leader.ControllersKey, ID: cfg.HostName, Clock: cfg.Clock, Options: cfg.Leader, Log: cfg.Log}
	e.Run(ctx, lead)
}

// reportSelf puts this node's own view of its control plane, and its version, into h.
func reportSelf(h *v1.Host, r selfReport) {
	h.Status.Version = version.Version
	cp := v1.ControlPlaneStatus{}
	if h.Status.ControlPlane != nil {
		cp = *h.Status.ControlPlane
	}
	cp.APIURL, cp.Store = r.apiURL, r.store
	cp.PeerURL = ""
	if r.peerURL != nil {
		cp.PeerURL = r.peerURL()
	}
	h.Status.ControlPlane = &cp
}

func (cfg Config) self(apiAddr string, st *cpStore) selfReport {
	r := selfReport{store: StoreSQLite}
	if apiAddr != "" {
		_, port, _ := net.SplitHostPort(apiAddr)
		r.apiURL = "https://" + net.JoinHostPort(cfg.Address, port)
	}
	if st.etcd != nil {
		srv := st.etcd
		r.store = StoreEtcd
		r.peerURL = func() string {
			if len(srv.Etcd.Peers) == 0 {
				return ""
			}
			return srv.PeerURL
		}
	}
	return r
}

// startStateOnly runs a light system node: the etcd member, its certificate rotation (in
// openStore), and a heartbeat written into the store. No API, no controllers, no admin socket.
func startStateOnly(ctx context.Context, cfg Config, st *cpStore) (*Running, error) {
	if st.etcd == nil {
		_ = st.Close()
		return nil, errors.New("a state-only node needs --store etcd")
	}
	r := &Running{done: make(chan struct{})}
	rep := cfg.self("", st)
	go func() {
		storeHeartbeat(ctx, st, cfg, rep)
		_ = st.Close()
		close(r.done)
	}()
	cfg.Log("light system node %s: etcd member only (peer %s), no API", cfg.HostName, st.etcd.PeerURL)
	return r, nil
}

// storeHeartbeat keeps this host's Ready condition fresh by writing its Host into the store (a
// compare-and-swap on its revision, like any update), for a node with no API server.
func storeHeartbeat(ctx context.Context, st store.Store, cfg Config, rep selfReport) {
	key := store.Key{Kind: "Host", Name: cfg.HostName}
	tick := func() {
		for attempt := 0; attempt < 5; attempt++ {
			o, err := st.Get(ctx, key)
			if err != nil {
				if ctx.Err() == nil {
					cfg.Log("heartbeat: %v", err)
				}
				return
			}
			obj, _, err := v1.Decode(o.Data)
			if err != nil {
				cfg.Log("heartbeat: %v", err)
				return
			}
			h := obj.(*v1.Host)
			now := cfg.Clock.Now()
			meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "StoreMemberUp",
				Message: "light system node: store member, no API", ObservedGeneration: h.Generation}, now.UTC().Truncate(time.Second))
			setHeartbeat(h, now)
			reportSelf(h, rep)
			h.ResourceVersion = ""
			data, err := json.Marshal(h)
			if err != nil {
				return
			}
			if _, err := st.Update(ctx, key, data, o.Revision); errors.Is(err, store.ErrConflict) {
				continue
			} else if err != nil && ctx.Err() == nil {
				cfg.Log("heartbeat: %v", err)
			}
			return
		}
	}
	tick()
	t := time.NewTicker(cfg.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// loadOrCreateCA loads the cluster CA (made on the first control plane's first start, or written by a join).
func loadOrCreateCA(cfg Config) (*pki.CA, error) {
	pkiDir := filepath.Join(cfg.DataDir, "pki")
	ca, err := pki.LoadCA(pkiDir)
	if errors.Is(err, os.ErrNotExist) && cfg.Join == nil {
		cfg.Log("creating the cluster CA in %s", pkiDir)
		if ca, err = pki.NewCA(cfg.ClusterName, cfg.Clock.Now()); err == nil {
			err = ca.Save(pkiDir)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("cluster CA: %w", err)
	}
	return ca, nil
}
