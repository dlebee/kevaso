package agent_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/agent"
)

// holdEverything judges every answer older than what this worker saw (a held worker, §0.7).
type holdEverything struct{}

func (holdEverything) Sending() int64                                             { return 0 }
func (holdEverything) Answer(int64, client.ControlPlaneSeen)                      {}
func (holdEverything) Judged(int64, client.ControlPlaneSeen, bool) client.Verdict { return client.Hold }

// K-097, the local endpoint's half (host lane: internal/agent/endpoint.go). A held worker is still
// handed its control plane's answers (client.Hold is handed over), and the endpoint relays them to
// the silo as they come: a secret value, a signature or a port lease from a control plane older
// than what the worker saw (a grant revoked since a backup is honoured again). The network's
// rules, DNS and gate now serve the last trusted state while held (internal/worker, served.go);
// the endpoint has no secret on disk to serve, so it must refuse instead.
//
// Fix: give the Endpoint a `Held func() bool` (the worker's Watermark.Held, as NetworkOptions.Held
// is) and, in ServeHTTP before the relay, answer 503 "this host is held (its control plane is
// older than what it saw): nothing is asked of it until that ends" without calling the control
// plane. Alternatively, after the relay, refuse an answer the client's judge called Hold (that
// needs api/client to say so: control lane). Then remove the skip.
func TestAHeldEndpointRelaysNoOlderAnswer(t *testing.T) {
	t.Skip("K-097, host lane: the local endpoint relays a held control plane's answers (internal/agent/endpoint.go ServeHTTP)")
	cp := &fakeBroker{answer: func(client.AgentBrokerRequest) client.BrokerResponse {
		return client.BrokerResponse{Value: []byte("revoked-since"), Version: 1}
	}}
	cps := httptest.NewServer(cp)
	defer cps.Close()
	c := client.New(cps.URL)
	c.ControlPlane = holdEverything{}
	ep := &agent.Endpoint{Client: c, HostName: "hv1", Hosts: []string{"169.254.42.1", "169.254.42.1:80"}}
	ep.Register(netip.MustParseAddr("127.0.0.1"), nodeID)
	srv := httptest.NewUnstartedServer(ep)
	srv.Config = ep.Server()
	srv.Start()
	defer srv.Close()
	r := &endpointRig{cp: cp, ep: ep, url: srv.URL}
	resp, body := r.do(t, http.MethodGet, "/v1/secrets/db-password", nil, nil)
	if resp.StatusCode == http.StatusOK || body == "revoked-since" {
		t.Fatalf("held: the endpoint gave the silo the older control plane's answer: %d %q", resp.StatusCode, body)
	}
}
