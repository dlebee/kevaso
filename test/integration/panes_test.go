package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/guest"
	"kevaso.com/core/internal/panes"
	"kevaso.com/core/sdk/kri"
)

// Design §10.1 through the real API and the host's broker: a silo with panes on reports status and
// HTML panes over its own channel; the control plane keeps the latest one, never as anything but
// an opaque bundle served as a download; a silo without panes, or past its limits, is refused; the
// silo can't speak for another; people with a role read panes, nobody writes them through the API.
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
	agentSilo := place("claude-1", &v1.PaneConfig{Enabled: true, Allow: []string{"status", "html"}, MaxPanes: 2})
	quiet := place("quiet", nil)
	statusOnly := place("plain", &v1.PaneConfig{Enabled: true})

	dir, _ := os.MkdirTemp("/tmp", "kvp")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ch := channels{dir}
	hv1 := &agent.Broker{Client: c.host(t, "hv1")}
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	for _, s := range []*v1.Silo{agentSilo, quiet, statusOnly} {
		if err := hv1.Ensure(ctx, ch, kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID}); err != nil {
			t.Fatal(err)
		}
	}
	report := func(s *v1.Silo, r v1.PaneReport) error {
		_, err := guest.Call(ctx, ch.dialer(s.UID), client.BrokerRequest{Op: client.OpPane, Pane: &r})
		return err
	}
	p := 0.57
	overview := v1.PaneReport{Pane: "overview", Kind: "status", Title: "refactor", State: "needs-you", Progress: &p, Message: "Keep legacy rounding?", TTL: "60s",
		Silo: "quiet", SiloUID: quiet.UID} // claims to be another silo: ignored, the channel says who

	if err := report(agentSilo, overview); err != nil {
		t.Fatal(err)
	}
	if err := report(quiet, overview); err == nil || !strings.Contains(err.Error(), "off") {
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
	overview.State = "running"
	if err := report(agentSilo, overview); err != nil {
		t.Fatal(err)
	}
	_ = vi.Get(c.ctx, "Pane", "web3", "claude-1.overview", &got)
	if got.Spec.State != "running" || got.Status.Updates != 2 {
		t.Fatalf("after an update: %+v", got.Spec)
	}

	// HTML: the bundle goes up once, by digest; the pane points at it.
	bundle := []byte(`<script>new WebSocket("wss://evil.example")</script>`)
	up, err := guest.Call(ctx, ch.dialer(agentSilo.UID), client.BrokerRequest{Op: client.OpPaneBundle, Payload: bundle})
	if err != nil || up.Digest != panes.Digest(bundle) {
		t.Fatalf("bundle upload: %+v %v", up, err)
	}
	html := v1.PaneReport{Pane: "fleet-3d", Kind: "html", Bundle: up.Digest, Data: json.RawMessage(`{"lit":3}`)}
	if err := report(agentSilo, html); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.Call(ctx, ch.dialer(statusOnly.UID), client.BrokerRequest{Op: client.OpPaneBundle, Payload: bundle}); err == nil {
		t.Fatal("a status-only silo uploaded a bundle")
	}
	unknown := html
	unknown.Bundle = panes.Digest([]byte("never uploaded"))
	if err := report(agentSilo, unknown); err == nil || !strings.Contains(err.Error(), "upload it first") {
		t.Fatalf("pane with a bundle nobody uploaded: %v", err)
	}
	// maxPanes 2: a third pane is refused.
	third := overview
	third.Pane = "third"
	if err := report(agentSilo, third); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("third pane: %v", err)
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

	// Rate: a burst past the limit is refused.
	refused := 0
	for range 30 {
		if err := report(statusOnly, v1.PaneReport{Pane: "spam", Kind: "status", State: "running"}); err != nil && strings.Contains(err.Error(), "too fast") {
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
