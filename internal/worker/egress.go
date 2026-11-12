package worker

import (
	"context"
	"crypto/x509"
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

	mu       sync.Mutex
	silos    func() []*v1.Silo
	grants   func() []*v1.Grant
	injected map[string]cachedInjections // by silo namespace/name
}

type cachedInjections struct {
	uid    string
	at     time.Time
	byHost map[string]gate.Injection
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

// local finds the silo on this host with address ip.
func (e *egress) local(ip netip.Addr) (*v1.Silo, bool) {
	for _, s := range e.silos() {
		if s.Status.Host == e.hostName && s.Status.Address == ip.String() {
			return s, true
		}
	}
	return nil, false
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
	e.mu.Lock()
	if c, ok := e.injected[key]; ok && c.uid == silo.UID && time.Since(c.at) < time.Minute {
		e.mu.Unlock()
		return c.byHost, nil
	}
	e.mu.Unlock()
	var resp client.BrokerResponse
	err := e.c.Call(ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
		Namespace: silo.Namespace, Name: silo.Name, UID: silo.UID, Host: e.hostName,
		Request: client.BrokerRequest{Op: client.OpInjections}}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	byHost := map[string]gate.Injection{}
	for _, in := range resp.Injections {
		byHost[in.Host] = gate.Injection{Header: in.Header, Value: in.Value}
	}
	e.mu.Lock()
	if e.injected == nil {
		e.injected = map[string]cachedInjections{}
	}
	e.injected[key] = cachedInjections{uid: silo.UID, at: time.Now(), byHost: byHost}
	e.mu.Unlock()
	return byHost, nil
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
		Injections: e.injections,
		OrigDst:    gate.OriginalDst,
		Upstream:   e.upstream,
		Log:        e.log,
	}
	e.log("egress gate on %s", addr)
	_ = g.Serve(ctx, l)
}
