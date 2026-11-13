package controlplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/etcd"
	"kevaso.com/core/internal/leader"
	"kevaso.com/core/internal/worker"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// cluster is several system nodes on loopback, each in its own temp dir.
type cluster struct {
	t     *testing.T
	nodes map[string]*node
	admin *client.Client // cluster-admin over TLS, every API URL (fails over)
	ca    []byte
	mu    sync.Mutex
	logs  []string
	// adminKeys are the cluster-admin's certificate and key.
	adminKeys [2][]byte
}

type node struct {
	name   string
	run    *Running
	cancel context.CancelFunc
	sock   string
	peer   string
	url    string
	data   string
}

func (n *node) dataDir(*cluster) string { return n.data }

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

func (c *cluster) log(name string) func(string, ...any) {
	return func(f string, a ...any) {
		c.mu.Lock()
		c.logs = append(c.logs, name+": "+fmt.Sprintf(f, a...))
		c.mu.Unlock()
	}
}

func (c *cluster) config(name string, stateOnly bool) (Config, *node) {
	sockDir, _ := os.MkdirTemp("/tmp", "kvha")
	c.t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	n := &node{name: name, sock: filepath.Join(sockDir, "admin.sock"), peer: freePort(c.t)}
	return Config{
		ClusterName: "ha", HostName: name, Address: "127.0.0.1", DataDir: c.t.TempDir(),
		Listen: "127.0.0.1:0", AdminSocket: n.sock, Heartbeat: 100 * time.Millisecond, HostLease: 2 * time.Second,
		Store: StoreEtcd, Etcd: EtcdConfig{ClientListen: "127.0.0.1:0", PeerListen: n.peer, UnsafeNoFsync: true},
		Leader:      leader.Options{Lease: 1500 * time.Millisecond, RenewDeadline: time.Second, RetryPeriod: 100 * time.Millisecond},
		MemberEvery: 150 * time.Millisecond, StateOnly: stateOnly, Log: c.log(name),
	}, n
}

func (c *cluster) start(cfg Config, n *node) {
	ctx, cancel := context.WithCancel(context.Background())
	r, err := Start(ctx, cfg)
	if err != nil {
		cancel()
		c.dump()
		c.t.Fatalf("start %s: %v", n.name, err)
	}
	n.run, n.cancel, n.data = r, cancel, cfg.DataDir
	if r.APIAddr != "" {
		n.url = "https://" + r.APIAddr
	}
	c.nodes[n.name] = n
	c.t.Cleanup(func() { cancel(); _ = r.Wait() })
}

func (c *cluster) dump() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.logs {
		c.t.Log(l)
	}
}

// newCluster starts the first control plane (etcd, a peer listener) and a cluster-admin client.
func newCluster(t *testing.T) *cluster {
	c := &cluster{t: t, nodes: map[string]*node{}}
	cfg, n := c.config("cp-1", false)
	ctx, cancel := context.WithCancel(context.Background())
	r, err := Start(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	n.run, n.cancel, n.url, n.data = r, cancel, "https://"+r.APIAddr, cfg.DataDir
	c.nodes[n.name] = n
	t.Cleanup(func() { cancel(); _ = r.Wait() })
	unix := client.NewUnix(n.sock)
	c.waitHost(unix, "cp-1", func(h *v1.Host) bool { return meta.IsTrue(h.Status.Conditions, "Ready") })
	key, csr, err := client.NewKeyAndCSR("ops")
	if err != nil {
		t.Fatal(err)
	}
	cert, ca, err := unix.SignUserCSR(context.Background(), "ops", csr)
	if err != nil {
		t.Fatal(err)
	}
	c.ca = ca
	if c.admin, err = client.NewTLS(n.url, ca, cert, key); err != nil {
		t.Fatal(err)
	}
	c.adminKeys = [2][]byte{cert, key}
	return c
}

// join declares a system node, gives it a one-time token, and starts it with --join, the way
// kvoadm host add --install control-plane does on a real machine.
func (c *cluster) join(name string, stateOnly bool) *node {
	ctx := context.Background()
	cfg, n := c.config(name, stateOnly)
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"},
		ObjectMeta: meta.ObjectMeta{Name: name, Annotations: map[string]string{etcd.AnnotationPeerURL: "https://" + n.peer}},
		Spec:       v1.HostSpec{Address: "127.0.0.1", Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{StateOnly: stateOnly}}}}
	if err := c.admin.Create(ctx, h); err != nil {
		c.t.Fatal(err)
	}
	var tok client.JoinTokenResponse
	if err := c.admin.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: name, Roles: []string{apiserver.RoleSystemNode}}, &tok); err != nil {
		c.t.Fatal(err)
	}
	cfg.Join = &JoinConfig{Servers: c.urls(), CA: c.ca, Token: tok.Token}
	cfg.Store, cfg.Etcd.PeerListen = "", "" // the join answer decides both
	cfg.Etcd.ClientListen = "127.0.0.1:0"
	cfg.Etcd.UnsafeNoFsync = true
	n.peer = strings.TrimPrefix(h.Annotations[etcd.AnnotationPeerURL], "https://")
	c.start(cfg, n)
	c.refreshAdmin()
	return n
}

func (c *cluster) urls() []string {
	var out []string
	for _, name := range []string{"cp-1", "cp-2", "cp-3", "cp-4"} {
		if n := c.nodes[name]; n != nil && n.url != "" {
			out = append(out, n.url)
		}
	}
	return out
}

func (c *cluster) refreshAdmin() {
	a, err := client.NewTLSEndpoints(c.urls(), c.ca, c.adminKeys[0], c.adminKeys[1])
	if err != nil {
		c.t.Fatal(err)
	}
	c.admin = a
}

func (c *cluster) waitHost(cl *client.Client, name string, ok func(*v1.Host) bool) *v1.Host {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		var h v1.Host
		if err := cl.Get(ctx, "Host", "", name, &h); err == nil && ok(&h) {
			return &h
		}
		select {
		case <-ctx.Done():
			c.dump()
			c.t.Fatalf("host %s: condition never held", name)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func voter(h *v1.Host) bool {
	return h.Status.ControlPlane != nil && h.Status.ControlPlane.Member == "voter" && meta.IsTrue(h.Status.Conditions, "Ready")
}

// leaderName is the system node whose Host says it leads (the member controller writes it).
func (c *cluster) leaderName(names ...string) string {
	c.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var leaders []string
		for _, n := range names {
			var h v1.Host
			if err := c.admin.Get(context.Background(), "Host", "", n, &h); err == nil && h.Status.ControlPlane != nil && h.Status.ControlPlane.Leader {
				leaders = append(leaders, n)
			}
		}
		if len(leaders) == 1 {
			return leaders[0]
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.dump()
	c.t.Fatal("no single leader shown")
	return ""
}

// A worker with a fake runtime: its agent dials a tunnel to every system node.
// echo answers every exec with the silo's name (the agent's tunnel is what's under test).
type echo struct{ kri.Runtime }

func (echo) Exec(_ context.Context, id kri.ID, req kri.ExecRequest) (int, error) {
	_, err := io.WriteString(req.Stdout, "hello from "+id.Name)
	return 0, err
}

func (c *cluster) worker(name string, servers ...string) (*client.Client, string) {
	if len(servers) == 0 {
		servers = c.urls()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.t.Cleanup(cancel)
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
		Spec: v1.HostSpec{Address: "127.0.0.2", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "cloud-hypervisor"}}}}}}
	if err := c.admin.Create(ctx, h); err != nil {
		c.t.Fatal(err)
	}
	var tok client.JoinTokenResponse
	if err := c.admin.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: name, Roles: []string{"worker"}}, &tok); err != nil {
		c.t.Fatal(err)
	}
	dir := c.t.TempDir()
	caFile, tokFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "join-token")
	_ = os.WriteFile(caFile, c.ca, 0o600)
	_ = os.WriteFile(tokFile, []byte(tok.Token), 0o600)
	wc, err := worker.Join(ctx, worker.JoinConfig{HostName: name, Server: strings.Join(servers, ","), CAFile: caFile, TokenFile: tokFile, DataDir: dir})
	if err != nil {
		c.t.Fatal(err)
	}
	var cur v1.Host
	if err := wc.Get(ctx, "Host", "", name, &cur); err != nil {
		c.t.Fatal(err)
	}
	cur.Status.Runtimes = map[string]v1.RuntimeStatus{"cloud-hypervisor": {State: "Ready"}}
	cur.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
	if err := wc.UpdateStatus(ctx, &cur); err != nil {
		c.t.Fatal(err)
	}
	go worker.Heartbeat(ctx, wc, name, 100*time.Millisecond, clock.Real{}, func(string, ...any) {}, nil)
	a := &agent.Agent{Client: wc, HostName: name, Runtimes: map[string]kri.Runtime{"cloud-hypervisor": echo{fake.New()}}, Clock: clock.Real{}, TunnelRefresh: 100 * time.Millisecond,
		OnEndpoints: func(s []string) { _ = worker.KeepServers(dir, s) }}
	go a.RunTunnels(ctx)
	return wc, dir
}

func (c *cluster) silo(name string) *v1.Silo {
	ctx := context.Background()
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor"}}
	if err := c.admin.Create(ctx, s); err != nil {
		c.t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var got v1.Silo
		if err := c.admin.Get(ctx, "Silo", "dev", name, &got); err == nil && got.Status.Host != "" {
			return &got
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.dump()
	c.t.Fatalf("silo %s never scheduled", name)
	return nil
}

// execAt runs a command in a silo through one system node's API, retrying while the host's tunnel
// to that node is still connecting.
func (c *cluster) execAt(url, silo string) string {
	c.t.Helper()
	cl, err := client.NewTLS(url, c.ca, c.adminKeys[0], c.adminKeys[1])
	if err != nil {
		c.t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		var out bytes.Buffer
		_, err := cl.Exec(context.Background(), "dev", silo, []string{"hostname"}, nil, &out, nil)
		if err == nil {
			return out.String()
		}
		if time.Now().After(deadline) {
			c.dump()
			c.t.Fatalf("exec %s at %s: %v", silo, url, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestThreeControlPlanesJoinAndSurviveLosingOne(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three etcd members")
	}
	c := newCluster(t)
	c.join("cp-2", false)
	c.join("cp-3", false)
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		h := c.waitHost(c.admin, n, voter)
		if h.Status.ControlPlane.APIURL == "" || h.Status.ControlPlane.Store != StoreEtcd || h.Status.Version == "" {
			t.Fatalf("%s reports %+v version %q", n, h.Status.ControlPlane, h.Status.Version)
		}
	}
	// One etcd cluster: what's written at one node reads back at every other.
	ctx := context.Background()
	if err := c.admin.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	for _, u := range c.urls() {
		cl, _ := client.NewTLS(u, c.ca, c.adminKeys[0], c.adminKeys[1])
		var ns v1.Namespace
		if err := cl.Get(ctx, "Namespace", "", "dev", &ns); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
	}
	lead := c.leaderName("cp-1", "cp-2", "cp-3")

	c.worker("w1")
	if s := c.silo("before"); s.Status.Host != "w1" {
		t.Fatalf("placed on %q", s.Status.Host)
	}
	for _, u := range c.urls() { // exec routes at every system node: the host has a tunnel to each
		if out := c.execAt(u, "before"); out != "hello from before" {
			t.Fatalf("exec at %s: %q", u, out)
		}
	}

	// Lose the controllers' leader, with nothing stopped beforehand.
	gone := c.nodes[lead]
	gone.cancel()
	_ = gone.run.Wait()
	var rest []string
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		if n != lead {
			rest = append(rest, n)
		}
	}
	// The API still answers (the client fails over), another node takes the lead, a new silo is
	// still scheduled, and exec still routes through the nodes left.
	if newLead := c.leaderName(rest...); newLead == lead {
		t.Fatalf("leader still %s", lead)
	}
	if s := c.silo("after"); s.Status.Host != "w1" {
		t.Fatalf("placed on %q", s.Status.Host)
	}
	for _, n := range rest {
		if out := c.execAt(c.nodes[n].url, "after"); out != "hello from after" {
			t.Fatalf("exec at %s: %q", n, out)
		}
	}
	if l, err := c.admin.List(ctx, "Host", ""); err != nil || len(l.Items) != 4 {
		t.Fatalf("hosts after losing %s: %v", lead, err)
	}
}

// A worker set up while there was one control plane (its --server names only that one) keeps
// reaching the cluster when that one is lost after more joined: its agent learns the others from
// their Hosts, and keeps them for its next start. (On real machines, before this, the worker
// stopped heartbeating, went NotReady and got no silos the moment cp-1 was gone.)
func TestWorkerSetUpBeforeTheOtherSystemNodesSurvivesLosingTheFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three etcd members")
	}
	c := newCluster(t)
	first := c.nodes["cp-1"].url
	wc, dir := c.worker("w1", first)
	c.join("cp-2", false)
	c.join("cp-3", false)
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		c.waitHost(c.admin, n, voter)
	}
	deadline := time.Now().Add(20 * time.Second)
	for len(wc.Endpoints()) < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("the worker's client knows %v", wc.Endpoints())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := worker.Servers(first, dir); len(got) != 3 || got[0] != first {
		t.Fatalf("kept for the next start: %v", got)
	}

	gone := c.nodes["cp-1"]
	gone.cancel()
	_ = gone.run.Wait()
	lost := time.Now()
	c.waitHost(c.admin, "w1", func(h *v1.Host) bool {
		return h.Status.LastHeartbeat != nil && h.Status.LastHeartbeat.After(lost) && meta.IsTrue(h.Status.Conditions, "Ready")
	})
	c.leaderName("cp-2", "cp-3")
	if err := c.admin.Create(context.Background(), &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	if s := c.silo("after"); s.Status.Host != "w1" {
		t.Fatalf("placed on %q", s.Status.Host)
	}
}

// kvoadm host remove of a system node that is nothing else: the Host can't be left with no
// component, so it's deleted held by the member finalizer, and goes only once the member
// controller removed its member. (On real machines, before this, the removal failed with a 422:
// "a host needs at least one component".)
func TestRemoveASystemNodeThatIsOnlyThat(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three etcd members")
	}
	c := newCluster(t)
	c.join("cp-2", false)
	c.join("cp-3", false)
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		c.waitHost(c.admin, n, voter)
	}
	ctx := context.Background()
	var out bytes.Buffer
	if err := kvoadm.RemoveSystemNode(ctx, c.admin, "cp-3", false, &out); err == nil || !strings.Contains(err.Error(), "remove the host instead") {
		t.Fatalf("uninstall from a host with nothing else: %v", err)
	}
	if err := kvoadm.RemoveSystemNode(ctx, c.admin, "cp-3", true, &out); err != nil {
		c.dump()
		t.Fatalf("remove: %v\n%s", err, out.String())
	}
	if i, j := strings.Index(out.String(), "left the store"), strings.Index(out.String(), "removed from the cluster"); i < 0 || j < i {
		t.Fatalf("output:\n%s", out.String())
	}
	var h v1.Host
	if err := c.admin.Get(ctx, "Host", "", "cp-3", &h); !client.IsNotFound(err) {
		t.Fatalf("cp-3 still there: %v %+v", err, h.ObjectMeta)
	}
	// The member went before the Host: the member controller logged the removal, then the release.
	c.mu.Lock()
	logs := strings.Join(c.logs, "\n")
	c.mu.Unlock()
	i, j := strings.Index(logs, "member controller: Remove cp-3"), strings.Index(logs, "member controller: cp-3 left the store")
	if i < 0 || j < i {
		t.Fatalf("member controller's log:\n%s", logs)
	}
	for _, n := range []string{"cp-1", "cp-2"} {
		c.waitHost(c.admin, n, voter)
	}
}

// Two full system nodes and a light one: the light node is a voter, holds no master key, serves
// no API, and its vote keeps the store writable when one full node is lost.
func TestLightNodeIsTheThirdVoteOfTwo(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three etcd members")
	}
	c := newCluster(t)
	c.join("cp-2", false)
	light := c.join("cp-3", true)
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		c.waitHost(c.admin, n, voter)
	}
	h := c.waitHost(c.admin, "cp-3", voter)
	if h.Status.ControlPlane.APIURL != "" || light.url != "" {
		t.Fatalf("the light node serves an API: %+v", h.Status.ControlPlane)
	}
	if h.Status.Conditions[0].Reason != "StoreMemberUp" {
		t.Fatalf("light node's Ready: %+v", h.Status.Conditions)
	}
	if _, err := os.Stat(filepath.Join(light.dataDir(c), "kms", "local.json")); err == nil {
		t.Fatal("the light node got the master key")
	}
	lead := c.leaderName("cp-1", "cp-2")
	gone := c.nodes[lead]
	gone.cancel()
	_ = gone.run.Wait()
	other := map[string]string{"cp-1": "cp-2", "cp-2": "cp-1"}[lead]
	if l := c.leaderName(other); l != other {
		t.Fatal(l)
	}
	ctx := context.Background()
	if err := c.admin.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "still-writable"}}); err != nil {
		t.Fatalf("a write with one full node and the light node left: %v", err)
	}
}

// A join is refused, and its token left unspent, on a cluster still on SQLite; a wrong token is
// refused outright.
func TestJoinRefusals(t *testing.T) {
	data := t.TempDir()
	sockDir, _ := os.MkdirTemp("/tmp", "kvha")
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "admin.sock")
	r, stop := start(t, data, sock)
	defer stop()
	unix := client.NewUnix(sock)
	waitReady(t, unix)
	ctx := context.Background()
	_ = unix.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "cp-2"},
		Spec: v1.HostSpec{Address: "127.0.0.1", Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{}}}})
	var tok client.JoinTokenResponse
	if err := unix.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: "cp-2", Roles: []string{apiserver.RoleSystemNode}}, &tok); err != nil {
		t.Fatal(err)
	}
	anon, err := client.NewTLS("https://"+r.APIAddr, r.CA.PEM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = anon.JoinSystemNode(ctx, client.SystemNodeJoinRequest{Token: tok.Token, Host: "cp-2", Recipient: []byte("k")})
	var ce *client.Error
	if !errorsAs(err, &ce) || ce.Reason != "StoreNotHA" {
		t.Fatalf("join on SQLite: %v", err)
	}
	_, err = anon.JoinSystemNode(ctx, client.SystemNodeJoinRequest{Token: "kvj_nope.nope", Host: "cp-2", Recipient: []byte("k")})
	if !errorsAs(err, &ce) || ce.Code != http.StatusUnauthorized {
		t.Fatalf("join with a wrong token: %v", err)
	}
}

func errorsAs(err error, target **client.Error) bool { return errors.As(err, target) }
