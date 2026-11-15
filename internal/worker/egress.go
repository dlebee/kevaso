package worker

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/gate"
)

// GatePort is where the egress gate listens on the silo bridge's gateway.
const GatePort = 15001

// egress runs this host's egress gate (design §8.1 tier 2, E025).
type egress struct {
	c        *client.Client
	hostName string
	ca       *gate.CA
	upstream *x509.CertPool // nil: the system roots
	log      func(string, ...any)
	bound    *loadedBindings // the loaded ruleset's ports and addresses

	mu       sync.Mutex
	silos    func() []*v1.Silo
	grants   func() []*v1.Grant
	now      func() time.Time            // nil: time.Now
	hosts    func() []*v1.Host           // nil: none known
	services func() []*v1.Service        // nil: none known
	injected map[string]cachedInjections // by silo namespace/name
}

type cachedInjections struct {
	uid    string
	at     time.Time // when the control plane gave them
	byHost map[string]gate.Injection
	said   bool // the log has said they are injected without the control plane
}

// InjectWithoutContact is how long a host that can't reach its control plane keeps injecting a
// secret it was given (K-076): the grant's own lifetime, an hour when the grant sets none. Grants
// have no lifetime of their own yet, so it is always this. After it, every injection is refused
// until the control plane answers again.
const InjectWithoutContact = time.Hour

// cutOff says whether err means the control plane didn't answer (the host is cut off from it),
// rather than answered with a refusal.
func cutOff(err error) bool {
	var ae *client.Error
	if errors.As(err, &ae) {
		return ae.Code >= 500
	}
	return true
}

// upstreamRoots is the system roots plus extraCA (a PEM file: a company proxy's CA, or a test's
// "internet"), or nil for the system roots alone.
func upstreamRoots(extraCA string) (*x509.CertPool, error) {
	if extraCA == "" {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	b, err := os.ReadFile(extraCA)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no certificate", extraCA)
	}
	return pool, nil
}

// ClusterAddresses are the addresses of this host and its cluster that a granted name must not
// lead to (K-057, K-092), beyond the private, loopback and link-local ranges the gate refuses
// anyway: every address this host has (ifaces), every Host's internal, external and mesh
// address, and the silos' and Services' load-balancer, egress and pool addresses. Pure.
func ClusterAddresses(ifaces []netip.Addr, hosts []*v1.Host, silos []*v1.Silo, svcs []*v1.Service) []netip.Prefix {
	var out []netip.Prefix
	seen := map[netip.Addr]bool{}
	add := func(a netip.Addr) {
		a = a.Unmap().WithZone("")
		if a.IsValid() && !a.IsUnspecified() && !seen[a] {
			seen[a] = true
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	parse := func(ss ...string) {
		for _, s := range ss {
			if a, err := netip.ParseAddr(s); err == nil {
				add(a)
			}
		}
	}
	for _, a := range ifaces {
		add(a)
	}
	for _, h := range hosts {
		parse(h.Internal(), h.External(), h.Status.Network.MeshIP)
	}
	for _, s := range silos {
		parse(s.Status.SiloIP, s.Status.Service.LoadBalancerIP, s.Status.Service.EgressIP)
		parse(s.Status.Service.HostAddresses...)
	}
	for _, sv := range svcs {
		parse(sv.Status.ClusterIP, sv.Status.LoadBalancerIP)
	}
	return out
}

// interfaceAddrs are this host's own addresses, every interface's.
func interfaceAddrs() []netip.Addr {
	as, _ := net.InterfaceAddrs()
	var out []netip.Addr
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip)
			}
		}
	}
	return out
}

// internal is ClusterAddresses now.
func (e *egress) internal() []netip.Prefix {
	var hosts []*v1.Host
	var svcs []*v1.Service
	if e.hosts != nil {
		hosts = e.hosts()
	}
	if e.services != nil {
		svcs = e.services()
	}
	return ClusterAddresses(interfaceAddrs(), hosts, e.silos(), svcs)
}

// local finds the silo on this host a connection from ip came from: the one whose port the
// loaded rules bind ip to (K-002). The bridge drops any other source on that port, so this is the
// port the packet came in on, which the silo can't choose; status.siloIP, which a stale or forged
// status could make anything, plays no part. Nothing is bound before the first ruleset loads.
func (e *egress) local(ip netip.Addr) (*v1.Silo, bool) {
	if e.bound == nil {
		return nil, false
	}
	tap, ok := e.bound.tap(ip)
	if !ok {
		return nil, false
	}
	return siloOnTap(e.hostName, e.silos(), tap)
}

// invalidate drops cached injections (a secret rotated or a grant changed): the next request
// gets the new value, and no silo ever held the old one.
func (e *egress) invalidate() {
	e.mu.Lock()
	e.injected = nil
	e.mu.Unlock()
}

func (e *egress) injections(ctx context.Context, key string) (map[string]gate.Injection, error) {
	var silo *v1.Silo
	for _, s := range e.silos() {
		if s.Namespace+"/"+s.Name == key && s.Status.Host == e.hostName {
			silo = s
		}
	}
	if silo == nil {
		return nil, fmt.Errorf("%s isn't on this host", key)
	}
	now := time.Now
	if e.now != nil {
		now = e.now
	}
	e.mu.Lock()
	c, cached := e.injected[key]
	cached = cached && c.uid == silo.UID
	if cached && now().Sub(c.at) < time.Minute {
		e.mu.Unlock()
		return c.byHost, nil
	}
	e.mu.Unlock()
	var resp client.BrokerResponse
	err := e.c.Call(ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
		Namespace: silo.Namespace, Name: silo.Name, UID: silo.UID, Host: e.hostName,
		Request: client.BrokerRequest{Op: client.OpInjections}}, &resp)
	if err != nil && cutOff(err) && cached {
		// Cut off (K-076): what the control plane last gave, until InjectWithoutContact.
		if age := now().Sub(c.at); age >= InjectWithoutContact {
			return nil, fmt.Errorf("the control plane hasn't answered for %s (%v): a secret is injected for at most %s without it, and again once it answers", age.Round(time.Second), err, InjectWithoutContact)
		}
		e.mu.Lock()
		if cur, ok := e.injected[key]; ok && cur.at.Equal(c.at) && !cur.said {
			cur.said = true
			e.injected[key] = cur
			e.log("egress gate: %s: the control plane can't be reached (%v): injecting what it gave %s ago, for at most %s", key, err, now().Sub(c.at).Round(time.Second), InjectWithoutContact)
		}
		e.mu.Unlock()
		return c.byHost, nil
	}
	if err != nil || resp.Error != "" { // refused: what was given before doesn't cover it
		e.mu.Lock()
		delete(e.injected, key)
		e.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s", resp.Error)
	}
	byHost := map[string]gate.Injection{}
	for _, in := range resp.Injections {
		byHost[in.Host] = gate.Injection{Header: in.Header, Value: in.Value, Approval: in.Approval, Secret: in.Secret}
	}
	e.mu.Lock()
	if e.injected == nil {
		e.injected = map[string]cachedInjections{}
	}
	e.injected[key] = cachedInjections{uid: silo.UID, at: now(), byHost: byHost}
	e.mu.Unlock()
	return byHost, nil
}

// askEvery is how often a request waiting for a person's yes asks again.
var askEvery = 2 * time.Second

// ask waits until a request may have an injected secret that needs a person's yes (design §8.7):
// it asks the control plane, then keeps asking with the pending approval's name until it's
// answered, expires, or the silo gives up on the request.
func (e *egress) ask(ctx context.Context, key, secret, host, method, path string) error {
	var silo *v1.Silo
	for _, s := range e.silos() {
		if s.Namespace+"/"+s.Name == key && s.Status.Host == e.hostName {
			silo = s
		}
	}
	if silo == nil {
		return fmt.Errorf("%s isn't on this host", key)
	}
	req := client.BrokerRequest{Op: client.OpAskInject, Name: secret, Host: host, Method: method, Path: path}
	told := ""
	for {
		var resp client.BrokerResponse
		err := e.c.Call(ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
			Namespace: silo.Namespace, Name: silo.Name, UID: silo.UID, Host: e.hostName, Request: req}, &resp)
		switch {
		case err != nil:
			return err
		case resp.Error != "":
			return fmt.Errorf("%s", resp.Error)
		case resp.Pending == nil:
			return nil
		}
		if told != resp.Pending.Name {
			e.log("egress gate: %s %s https://%s%s waits for approval %s/%s", key, method, host, path, resp.Pending.Namespace, resp.Pending.Name)
			told = resp.Pending.Name
		}
		req.Approval = resp.Pending.Name
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped waiting for approval %s: %w", resp.Pending.Name, ctx.Err())
		case <-time.After(askEvery):
		}
	}
}

// run serves the gate on the bridge's gateway until ctx ends.
func (e *egress) run(ctx context.Context) {
	addr := net.JoinHostPort(cloudhypervisor.Gateway.String(), strconv.Itoa(GatePort))
	var l net.Listener
	for {
		var err error
		if l, err = net.Listen("tcp", addr); err == nil {
			break
		}
		e.log("egress gate: %v (retrying)", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	go func() { <-ctx.Done(); _ = l.Close() }()
	g := &gate.Gate{
		CA: e.ca,
		Silo: func(ip netip.Addr) (gate.Policy, bool) {
			s, ok := e.local(ip)
			if !ok {
				return gate.Policy{}, false
			}
			return gate.PolicyFor(s, e.grants()), true
		},
		Internal:   e.internal,
		Injections: e.injections,
		Ask:        e.ask,
		OrigDst:    gate.OriginalDst,
		Upstream:   e.upstream,
		Log:        e.log,
	}
	e.log("egress gate on %s", addr)
	_ = g.Serve(ctx, l)
}
