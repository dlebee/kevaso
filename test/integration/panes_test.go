package integration

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/panes"
)

// paneServer is the silo's own software: a small HTTP server answering the pane protocol's two
// GETs (ADR 0009), whatever the test puts in it.
type paneServer struct {
	mu      sync.Mutex
	list    string
	bundles map[string][]byte
	port    int
}

func newPaneServer(t *testing.T) *paneServer {
	t.Helper()
	ps := &paneServer{bundles: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps.mu.Lock()
		defer ps.mu.Unlock()
		if d, ok := strings.CutPrefix(r.URL.Path, "/panes/bundles/"); ok && ps.bundles[d] != nil {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(ps.bundles[d])
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, ps.list)
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	ps.port, _ = strconv.Atoi(port)
	return ps
}

func (ps *paneServer) answer(list string, bundles ...[]byte) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.list = list
	for _, b := range bundles {
		ps.bundles[panes.Digest(b)] = b
	}
}

// Design §10.1 through the real API: a silo with panes on answers its host's two GETs; the host
// fetches, checks and relays; the control plane checks again and keeps the latest report, never as
// anything but an opaque bundle served as a download; a silo without panes, or past its limits,
// is refused; what a silo says about who it is is ignored; people with a role read panes, nobody
// writes them through the API.
func TestPanes(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	place := func(name string, cfg *v1.PaneConfig) *v1.Silo {
		t.Helper()
		s := silo(name, "web3")
		s.Spec.Panes = cfg
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host = "hv1"
		if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	ps, plain := newPaneServer(t), newPaneServer(t)
	agentSilo := place("claude-1", &v1.PaneConfig{HTTP: &v1.PaneHTTP{Port: ps.port}, Allow: []string{"status", "html"}, MaxPanes: 2})
	quiet := place("quiet", nil)
	statusOnly := place("plain", &v1.PaneConfig{HTTP: &v1.PaneHTTP{Port: plain.port}})
	hv1 := c.host(t, "hv1")
	var states []string
	fetcher := func(s *v1.Silo) *agent.PaneFetcher {
		return &agent.PaneFetcher{Client: hv1, HostName: "hv1", Silo: s, Address: "127.0.0.1",
			OnState: func(ok bool, reason, msg string) { states = append(states, reason+": "+msg) }}
	}
	fa := fetcher(agentSilo)
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	// What a host relays for a silo, as the control plane sees it.
	relay := func(s *v1.Silo, req client.BrokerRequest) error {
		var resp client.BrokerResponse
		if err := hv1.Call(ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{Namespace: s.Namespace, Name: s.Name, UID: s.UID, Request: req}, &resp); err != nil {
			return err
		}
		if resp.Error != "" {
			return errors.New(resp.Error)
		}
		return nil
	}

	// Claims to be another silo: ignored, the host says who.
	ps.answer(`{"panes": [{"pane": "overview", "kind": "status", "title": "refactor", "state": "needs-you", "progress": 0.57,
		"message": "Keep legacy rounding?", "ttl": "60s", "silo": "quiet", "siloUID": "` + quiet.UID + `"}]}`)
	if err := fa.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	// A silo without panes is never fetched; a host relaying for it anyway is refused.
	if err := relay(quiet, client.BrokerRequest{Op: client.OpPane, Pane: &v1.PaneReport{Pane: "x", Kind: "status"}}); err == nil || !strings.Contains(err.Error(), "off") {
		t.Fatalf("a silo without panes: %v", err)
	}

	c.bind(t, "vi", "ClusterRole", "viewer")
	vi := c.as(t, "vi")
	var got v1.Pane
	if err := vi.Get(c.ctx, "Pane", "web3", "claude-1.overview", &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Silo != "claude-1" || got.Spec.SiloUID != agentSilo.UID || got.Spec.State != "needs-you" || got.Status.Updates != 1 {
		t.Fatalf("pane: %+v", got)
	}
	// Latest wins.
	ps.answer(`{"panes": [{"pane": "overview", "kind": "status", "title": "refactor", "state": "running", "ttl": "60s"}]}`)
	if err := fa.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	_ = vi.Get(c.ctx, "Pane", "web3", "claude-1.overview", &got)
	if got.Spec.State != "running" || got.Status.Updates != 2 {
		t.Fatalf("after an update: %+v", got.Spec)
	}

	// HTML: the host fetches the bundle once, by digest; the pane points at it.
	bundle := []byte(`<script>new WebSocket("wss://evil.example")</script>`)
	digest := panes.Digest(bundle)
	ps.answer(`{"panes": [{"pane": "overview", "kind": "status", "title": "refactor", "state": "running", "ttl": "60s"},
		{"pane": "fleet-3d", "kind": "html", "bundle": "`+digest+`", "data": {"lit": 3}}]}`, bundle)
	if err := fa.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := vi.Get(c.ctx, "Pane", "web3", "claude-1.fleet-3d", &got); err != nil || got.Spec.Bundle != digest || string(got.Spec.Data) != `{"lit":3}` {
		t.Fatalf("html pane: %+v %v", got.Spec, err)
	}
	// A status-only silo answering an HTML pane: the host cuts it off; and the control plane
	// refuses its bundle anyway.
	plain.answer(`{"panes": [{"pane": "fleet-3d", "kind": "html", "bundle": "`+digest+`"}]}`, bundle)
	if err := fetcher(statusOnly).Fetch(ctx); err == nil || !strings.Contains(err.Error(), "isn't allowed") || !strings.HasPrefix(states[len(states)-1], "CutOff") {
		t.Fatalf("html from a status-only silo: %v %v", err, states)
	}
	if err := relay(statusOnly, client.BrokerRequest{Op: client.OpPaneBundle, Payload: bundle}); err == nil {
		t.Fatal("a status-only silo's bundle was stored")
	}
	unknown := v1.PaneReport{Pane: "fleet-3d", Kind: "html", Bundle: panes.Digest([]byte("never uploaded"))}
	if err := relay(agentSilo, client.BrokerRequest{Op: client.OpPane, Pane: &unknown}); err == nil || !strings.Contains(err.Error(), "upload it first") {
		t.Fatalf("pane with a bundle nobody uploaded: %v", err)
	}
	// maxPanes 2: a third pane cuts the silo off at its host; the control plane refuses it too.
	ps.answer(`{"panes": [{"pane": "overview", "kind": "status"}, {"pane": "fleet-3d", "kind": "html", "bundle": "` + digest + `"}, {"pane": "third", "kind": "status"}]}`)
	if err := fa.Fetch(ctx); err == nil || !strings.Contains(err.Error(), "at most 2") {
		t.Fatalf("third pane at the host: %v", err)
	}
	if err := relay(agentSilo, client.BrokerRequest{Op: client.OpPane, Pane: &v1.PaneReport{Pane: "third", Kind: "status"}}); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("third pane at the control plane: %v", err)
	}

	// The bundle comes back only as a download nothing renders.
	body, h, err := vi.Fetch(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/panes/claude-1.fleet-3d/bundle")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(bundle) || h.Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(h.Get("Content-Disposition"), "attachment") || h.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(h.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("bundle download: %v %q", h, body)
	}
	// A host can't fetch bundles; nobody writes panes through the API.
	if _, err := c.host(t, "hv2").Raw(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/panes/claude-1.fleet-3d/bundle"); status(err) != http.StatusForbidden {
		t.Fatalf("host fetched a bundle: %v", err)
	}
	forged := got
	forged.Spec.Message = "forged"
	if err := c.admin.Update(c.ctx, &forged); status(err) != http.StatusMethodNotAllowed {
		t.Fatalf("pane written through the API: %v", err)
	}

	// Rate: a burst past the limit is refused by the control plane too, whatever a host relays.
	refused := 0
	for range 30 {
		if err := relay(statusOnly, client.BrokerRequest{Op: client.OpPane, Pane: &v1.PaneReport{Pane: "spam", Kind: "status", State: "running"}}); err != nil && strings.Contains(err.Error(), "too fast") {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("30 reports at once all went through")
	}

	// The silo goes: its panes and bundles go with the sweep.
	if err := c.admin.Delete(c.ctx, "Silo", "web3", "claude-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.srv.SweepPanes(c.ctx); err != nil {
		t.Fatal(err)
	}
	if err := vi.Get(c.ctx, "Pane", "web3", "claude-1.overview", &got); status(err) != http.StatusNotFound {
		t.Fatalf("pane after its silo is gone: %v", err)
	}
}
