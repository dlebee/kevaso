package agent_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
)

// fakeBroker stands in for the control plane's POST /agent/broker: it records what the host relays
// and answers with answer.
type fakeBroker struct {
	mu     sync.Mutex
	got    []client.AgentBrokerRequest
	answer func(client.AgentBrokerRequest) client.BrokerResponse
}

func (f *fakeBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req client.AgentBrokerRequest
	if r.URL.Path != client.PathAgentBroker || json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "no", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.got = append(f.got, req)
	answer := f.answer
	f.mu.Unlock()
	resp := client.BrokerResponse{}
	if answer != nil {
		resp = answer(req)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeBroker) calls() []client.AgentBrokerRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]client.AgentBrokerRequest(nil), f.got...)
}

type endpointRig struct {
	cp  *fakeBroker
	ep  *agent.Endpoint
	url string
}

var nodeID = kri.ID{Namespace: "web3", Name: "node", UID: "uid-node"}

// newEndpoint serves an endpoint on loopback, with 127.0.0.1 registered as silo web3/node: the
// arrival point (the source address) is the only thing that says who asks.
func newEndpoint(t *testing.T) *endpointRig {
	t.Helper()
	cp := &fakeBroker{}
	cps := httptest.NewServer(cp)
	t.Cleanup(cps.Close)
	ep := &agent.Endpoint{Client: client.New(cps.URL), HostName: "hv1", Hosts: []string{"169.254.42.1", "169.254.42.1:80"}}
	ep.Register(netip.MustParseAddr("127.0.0.1"), nodeID)
	srv := httptest.NewUnstartedServer(ep)
	srv.Config = ep.Server()
	srv.Start()
	t.Cleanup(srv.Close)
	return &endpointRig{cp: cp, ep: ep, url: srv.URL}
}

// do sends a request as a silo would (the header, the endpoint's Host) after edit changes it.
func (r *endpointRig) do(t *testing.T, method, path string, body []byte, edit func(*http.Request)) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, r.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "169.254.42.1"
	req.Header.Set("Kevaso-Local", "1")
	if edit != nil {
		edit(req)
	}
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(b)
}

func TestEndpointIdentityFromArrivalOnly(t *testing.T) {
	r := newEndpoint(t)
	r.cp.answer = func(client.AgentBrokerRequest) client.BrokerResponse {
		return client.BrokerResponse{Value: []byte("pw-1"), Version: 3}
	}
	// Whatever the request says about who it is, the host says web3/node.
	resp, body := r.do(t, http.MethodGet, "/v1/secrets/db-password/password?namespace=other&name=victim&uid=x", nil, func(q *http.Request) {
		q.Header.Set("X-Kevaso-Silo", "other/victim")
		q.Header.Set("Authorization", "Bearer someone-else")
	})
	if resp.StatusCode != 200 || body != "pw-1" || resp.Header.Get("Kevaso-Version") != "3" || resp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("get: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	got := r.cp.calls()
	if len(got) != 1 || got[0].Namespace != "web3" || got[0].Name != "node" || got[0].UID != "uid-node" || got[0].Host != "hv1" ||
		got[0].Request.Op != client.OpGetSecret || got[0].Request.Name != "db-password" || got[0].Request.Key != "password" {
		t.Fatalf("relayed %+v", got)
	}
	// An address nobody registered (a silo whose grants need no endpoint) gets nothing, and the
	// control plane isn't asked.
	r.ep.Unregister("uid-node")
	if resp, _ := r.do(t, http.MethodGet, "/v1/secrets/db-password/password", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("unregistered: %d", resp.StatusCode)
	}
	if len(r.cp.calls()) != 1 {
		t.Fatal("an unregistered address reached the control plane")
	}
	// Registering another silo at the address moves it: the newest owner of an address is who asks.
	r.ep.Register(netip.MustParseAddr("127.0.0.1"), kri.ID{Namespace: "web3", Name: "other", UID: "uid-other"})
	r.do(t, http.MethodGet, "/v1/secrets/db-password/password", nil, nil)
	if got := r.cp.calls(); got[len(got)-1].Name != "other" {
		t.Fatalf("after re-register: %+v", got[len(got)-1])
	}
}

func TestEndpointRefusesBrowsersAndStrangers(t *testing.T) {
	r := newEndpoint(t)
	r.cp.answer = func(client.AgentBrokerRequest) client.BrokerResponse {
		return client.BrokerResponse{Value: []byte("pw")}
	}
	for name, c := range map[string]struct {
		method, path string
		edit         func(*http.Request)
		status       int
	}{
		"no header":            {"GET", "/v1/secrets/db/password", func(q *http.Request) { q.Header.Del("Kevaso-Local") }, 403},
		"header, wrong value":  {"GET", "/v1/secrets/db/password", func(q *http.Request) { q.Header.Set("Kevaso-Local", "true") }, 403},
		"Origin":               {"GET", "/v1/secrets/db/password", func(q *http.Request) { q.Header.Set("Origin", "http://169.254.42.1") }, 403},
		"empty Origin":         {"GET", "/v1/secrets/db/password", func(q *http.Request) { q.Header["Origin"] = []string{""} }, 403},
		"Sec-Fetch-Site":       {"GET", "/v1/secrets/db/password", func(q *http.Request) { q.Header.Set("Sec-Fetch-Site", "same-origin") }, 403},
		"rebound name as Host": {"GET", "/v1/secrets/db/password", func(q *http.Request) { q.Host = "evil.example" }, 403},
		"another port as Host": {"GET", "/v1/secrets/db/password", func(q *http.Request) { q.Host = "169.254.42.1:8080" }, 403},
		"CORS preflight":       {"OPTIONS", "/v1/secrets/db/password", nil, 405},
		"wrong method":         {"POST", "/v1/secrets/db/password", nil, 405},
		"trailing slash":       {"GET", "/v1/secrets/db/", nil, 404},
		"unclean path":         {"GET", "/v1//secrets/db", nil, 404},
		"dot dot":              {"GET", "/v1/keys/../secrets/db", nil, 404},
		"unknown route":        {"GET", "/v1/deliveries", nil, 404},
		"upper-case name":      {"GET", "/v1/secrets/DB/password", nil, 400},
		"bad duration":         {"GET", "/v1/secrets/db/password?for=forever", nil, 400},
		"bad approval":         {"GET", "/v1/secrets/db/password?approval=a%20b", nil, 400},
		"bad slot":             {"POST", "/v1/sign/key?slot=-1", nil, 400},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(r.cp.calls())
			resp, body := r.do(t, c.method, c.path, nil, c.edit)
			if resp.StatusCode != c.status {
				t.Fatalf("%d (want %d): %s", resp.StatusCode, c.status, body)
			}
			if loc := resp.Header.Get("Location"); loc != "" || resp.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("redirect or CORS header: %v", resp.Header)
			}
			if strings.Contains(body, "pw") || len(r.cp.calls()) != before {
				t.Fatalf("refused request reached the control plane or got the value: %q", body)
			}
			if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || !strings.Contains(body, `"error"`) {
				t.Fatalf("error isn't JSON: %v %q", resp.Header, body)
			}
		})
	}
}

// A secret the silo has no grant for answers exactly like one that doesn't exist (the control
// plane's NotFound), and other refusals map to their own statuses.
func TestEndpointRefusals(t *testing.T) {
	r := newEndpoint(t)
	r.cp.answer = func(q client.AgentBrokerRequest) client.BrokerResponse {
		switch q.Request.Name {
		case "not-mine", "does-not-exist":
			return client.BrokerResponse{Error: `no secret "` + q.Request.Name + `" for this silo`, Code: client.CodeNotFound}
		case "validator":
			return client.BrokerResponse{Error: "slashing protection: slot 7 already signed", Code: client.CodeConflict}
		}
		return client.BrokerResponse{Error: "approval gh-x: denied"}
	}
	a, ab := r.do(t, "GET", "/v1/secrets/not-mine/token", nil, nil)
	b, bb := r.do(t, "GET", "/v1/secrets/does-not-exist/token", nil, nil)
	if a.StatusCode != 404 || b.StatusCode != 404 || strings.ReplaceAll(ab, "not-mine", "X") != strings.ReplaceAll(bb, "does-not-exist", "X") {
		t.Fatalf("not granted vs missing: %d %q / %d %q", a.StatusCode, ab, b.StatusCode, bb)
	}
	if resp, _ := r.do(t, "POST", "/v1/sign/validator?slot=7", []byte("x"), nil); resp.StatusCode != 409 {
		t.Fatalf("slashing: %d", resp.StatusCode)
	}
	if resp, body := r.do(t, "GET", "/v1/secrets/gh-admin/token", nil, nil); resp.StatusCode != 403 || !strings.Contains(body, "denied") {
		t.Fatalf("denied: %d %s", resp.StatusCode, body)
	}
}

// A use that needs a person's yes answers 428 with the approval; asking again with it is relayed
// with it (so it doesn't replace the request), until the answer comes.
func TestEndpointPendingApproval(t *testing.T) {
	r := newEndpoint(t)
	exp := time.Date(2026, 11, 13, 15, 0, 0, 0, time.UTC)
	approved := false
	r.cp.answer = func(q client.AgentBrokerRequest) client.BrokerResponse {
		if !approved || q.Request.Approval != "gh-admin-x7k2p" {
			return client.BrokerResponse{Pending: &client.ApprovalWait{Namespace: "web3", Name: "gh-admin-x7k2p", ExpiresAt: exp}}
		}
		return client.BrokerResponse{Value: []byte("ghp-admin")}
	}
	resp, body := r.do(t, "GET", "/v1/secrets/gh-admin/token?for=30m&wait=10m", nil, nil)
	if resp.StatusCode != http.StatusPreconditionRequired || resp.Header.Get("Kevaso-Approval") != "gh-admin-x7k2p" || strings.Contains(body, "ghp") {
		t.Fatalf("pending: %d %v %s", resp.StatusCode, resp.Header, body)
	}
	var p struct {
		Pending client.ApprovalWait `json:"pending"`
		Error   string              `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &p); err != nil || p.Pending.Name != "gh-admin-x7k2p" || !p.Pending.ExpiresAt.Equal(exp) || !strings.Contains(p.Error, "kvo approve gh-admin-x7k2p -n web3") {
		t.Fatalf("pending body: %s %v", body, err)
	}
	if q := r.cp.calls()[0].Request; q.For != "30m" || q.Wait != "10m" || q.Approval != "" {
		t.Fatalf("first ask relayed %+v", q)
	}
	approved = true
	resp, body = r.do(t, "GET", "/v1/secrets/gh-admin/token?for=30m&approval=gh-admin-x7k2p", nil, nil)
	if resp.StatusCode != 200 || body != "ghp-admin" {
		t.Fatalf("after yes: %d %s", resp.StatusCode, body)
	}
	if q := r.cp.calls()[1].Request; q.Approval != "gh-admin-x7k2p" {
		t.Fatalf("poll relayed %+v", q)
	}
}

func TestEndpointSignKeysAndPorts(t *testing.T) {
	r := newEndpoint(t)
	until := time.Date(2026, 11, 13, 16, 0, 0, 0, time.UTC)
	r.cp.answer = func(q client.AgentBrokerRequest) client.BrokerResponse {
		switch q.Request.Op {
		case client.OpSign:
			return client.BrokerResponse{Signature: append([]byte{0xab}, q.Request.Payload...)}
		case client.OpPublicKey:
			return client.BrokerResponse{PublicKey: "00ff"}
		case client.OpPortOpen:
			return client.BrokerResponse{Until: &until, Clamped: true}
		}
		return client.BrokerResponse{Until: &until}
	}
	resp, body := r.do(t, "POST", "/v1/sign/validator-1-key?slot=7", []byte{1, 2}, nil)
	if resp.StatusCode != 200 || body != "ab0102\n" {
		t.Fatalf("sign: %d %q", resp.StatusCode, body)
	}
	if q := r.cp.calls()[0].Request; q.Slot == nil || *q.Slot != 7 || !bytes.Equal(q.Payload, []byte{1, 2}) {
		t.Fatalf("sign relayed %+v", q)
	}
	if resp, body := r.do(t, "GET", "/v1/keys/validator-1-key", nil, nil); resp.StatusCode != 200 || body != "00ff\n" {
		t.Fatalf("key: %d %q", resp.StatusCode, body)
	}
	resp, body = r.do(t, "POST", "/v1/ports/debug/open?for=1h", nil, nil)
	var open agent.PortOpened
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &open) != nil || open.Port != "debug" || !open.Until.Equal(until) || !open.Clamped {
		t.Fatalf("open: %d %s", resp.StatusCode, body)
	}
	if q := r.cp.calls()[2].Request; q.Op != client.OpPortOpen || q.Name != "debug" || q.For != "1h" {
		t.Fatalf("open relayed %+v", q)
	}
	if resp, body := r.do(t, "POST", "/v1/ports/debug/close", nil, nil); resp.StatusCode != 200 || !strings.Contains(body, `"closed":true`) {
		t.Fatalf("close: %d %s", resp.StatusCode, body)
	}
}

func TestEndpointLimits(t *testing.T) {
	r := newEndpoint(t)
	// A payload over 512 KiB isn't read, nor relayed.
	if resp, _ := r.do(t, "POST", "/v1/sign/k", bytes.Repeat([]byte("x"), 512<<10+1), nil); resp.StatusCode != http.StatusRequestEntityTooLarge || len(r.cp.calls()) != 0 {
		t.Fatalf("big payload: %d", resp.StatusCode)
	}
	// Headers past 8 KiB: refused by the server itself.
	if resp, _ := r.do(t, "GET", "/v1/secrets/db/password", nil, func(q *http.Request) { q.Header.Set("X-Pad", strings.Repeat("p", 16<<10)) }); resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("big headers: %d", resp.StatusCode)
	}
	// At most 8 at once per silo.
	release := make(chan struct{})
	entered := make(chan struct{}, 16)
	r.cp.answer = func(client.AgentBrokerRequest) client.BrokerResponse {
		entered <- struct{}{}
		<-release
		return client.BrokerResponse{Value: []byte("v")}
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); r.do(t, "GET", "/v1/secrets/db/password", nil, nil) }()
	}
	for range 8 {
		<-entered
	}
	if resp, _ := r.do(t, "GET", "/v1/secrets/db/password", nil, nil); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("9th at once: %d", resp.StatusCode)
	}
	close(release)
	wg.Wait()
	// The control plane gone: try again later.
	r2 := newEndpoint(t)
	r2.ep.Client = client.New("http://127.0.0.1:1")
	if resp, _ := r2.do(t, "GET", "/v1/secrets/db/password", nil, nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no control plane: %d", resp.StatusCode)
	}
}

// /v1/secrets/NAME/KEY relays the key and answers its bytes; /v1/secrets/NAME/* relays "*" and
// answers every key the grant gives as JSON; /v1/secrets/NAME alone is refused, never guessed.
func TestEndpointSecretKeys(t *testing.T) {
	r := newEndpoint(t)
	r.cp.answer = func(q client.AgentBrokerRequest) client.BrokerResponse {
		if q.Request.Key != "*" {
			return client.BrokerResponse{Value: []byte("pw"), Version: 3}
		}
		return client.BrokerResponse{Data: map[string][]byte{"password": []byte("pw"), "username": []byte("app")}, Version: 3}
	}
	resp, body := r.do(t, "GET", "/v1/secrets/db/password", nil, nil)
	if resp.StatusCode != 200 || body != "pw" || resp.Header.Get("Content-Type") != "application/octet-stream" || resp.Header.Get("Kevaso-Version") != "3" {
		t.Fatalf("one key: %d %q", resp.StatusCode, body)
	}
	if q := r.cp.calls()[0].Request; q.Op != client.OpGetSecret || q.Name != "db" || q.Key != "password" {
		t.Fatalf("relayed %+v", q)
	}
	for _, p := range []string{"/v1/secrets/db/*", "/v1/secrets/db/%2A"} {
		resp, body = r.do(t, "GET", p, nil, nil)
		var all agent.SecretKeys
		if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &all) != nil || string(all.Data["username"]) != "app" || string(all.Data["password"]) != "pw" ||
			all.Version != 3 || resp.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("%s, every key: %d %q", p, resp.StatusCode, body)
		}
		if q := r.cp.calls()[len(r.cp.calls())-1].Request; q.Key != "*" || q.Name != "db" {
			t.Fatalf("%s relayed %+v", p, q)
		}
	}
	// No key named: a 400 that shows both forms, and the control plane isn't asked.
	n := len(r.cp.calls())
	for _, p := range []string{"/v1/secrets/db", "/v1/secrets/db?for=1m"} {
		resp, body = r.do(t, "GET", p, nil, nil)
		if resp.StatusCode != 400 || !strings.Contains(body, "/v1/secrets/db/KEY for one key") || !strings.Contains(body, "/v1/secrets/db/* for every key") {
			t.Fatalf("%s: %d %q", p, resp.StatusCode, body)
		}
	}
	if len(r.cp.calls()) != n {
		t.Fatal("a request with no key reached the control plane")
	}
	for _, p := range []string{"/v1/secrets/db/a%20b", "/v1/secrets/db/.x", "/v1/secrets/db/**", "/v1/secrets/db/a*"} {
		if resp, _ := r.do(t, "GET", p, nil, nil); resp.StatusCode != 400 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := r.do(t, "GET", "/v1/secrets/db/password/more", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("a deeper path: %d", resp.StatusCode)
	}
}
