package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/panes"
)

// paneCP stands in for the control plane: it records relayed reports and bundles.
type paneCP struct {
	mu      sync.Mutex
	reports []v1.PaneReport
	bundles [][]byte
}

func (c *paneCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req client.AgentBrokerRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	c.mu.Lock()
	switch req.Request.Op {
	case client.OpPane:
		c.reports = append(c.reports, *req.Request.Pane)
	case client.OpPaneBundle:
		c.bundles = append(c.bundles, req.Request.Payload)
	}
	c.mu.Unlock()
	_ = json.NewEncoder(w).Encode(client.BrokerResponse{})
}

func (c *paneCP) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reports), len(c.bundles)
}

type paneRig struct {
	f      *PaneFetcher
	cp     *paneCP
	clk    *clock.Fake
	hits   map[string]int
	mu     sync.Mutex
	silo   http.HandlerFunc // the silo's pane server, swappable
	states []string
}

func newPaneRig(t *testing.T, cfg *v1.PaneConfig) *paneRig {
	t.Helper()
	r := &paneRig{cp: &paneCP{}, clk: clock.NewFake(time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)), hits: map[string]int{}}
	cps := httptest.NewServer(r.cp)
	t.Cleanup(cps.Close)
	silo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.mu.Lock()
		r.hits[q.URL.Path]++
		h := r.silo
		r.mu.Unlock()
		// The host's request carries nothing: no query, no body, no identity.
		if q.Method != http.MethodGet || q.URL.RawQuery != "" || q.Header.Get("Authorization") != "" || q.Header.Get("Cookie") != "" || q.ContentLength > 0 {
			t.Errorf("the host's request carried something: %s %s %v", q.Method, q.URL, q.Header)
		}
		h(w, q)
	}))
	t.Cleanup(silo.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(silo.URL, "http://"))
	cfg.HTTP.Port, _ = strconv.Atoi(port)
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "ux", Name: "agent", UID: "u1"}, Spec: v1.SiloSpec{Panes: cfg}}
	r.f = &PaneFetcher{Client: client.New(cps.URL), HostName: "hv1", Silo: s, Address: host, Clock: r.clk,
		OnState: func(ok bool, reason, msg string) { r.states = append(r.states, reason+": "+msg) }}
	return r
}

func (r *paneRig) serve(h http.HandlerFunc) {
	r.mu.Lock()
	r.silo = h
	r.mu.Unlock()
}

func (r *paneRig) hit(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[path]
}

func jsonList(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
}

const bundleHTML = "<!doctype html><p>hi</p>"

func htmlPaneServer(digest string, bundle string) http.HandlerFunc {
	return func(w http.ResponseWriter, q *http.Request) {
		if q.URL.Path == "/panes/bundles/"+digest {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, bundle)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"panes": [{"pane": "preview", "kind": "html", "bundle": %q, "data": {"n": 1}}]}`, digest)
	}
}

func on(allow ...string) *v1.PaneConfig {
	return &v1.PaneConfig{HTTP: &v1.PaneHTTP{}, Allow: allow, MaxPanes: 2, Every: "2s"}
}

func TestPaneFetchRelaysWhatChanged(t *testing.T) {
	r := newPaneRig(t, on("status", "html"))
	r.serve(jsonList(`{"panes": [{"pane": "build", "kind": "status", "state": "running", "progress": 0.4, "silo": "someone-else", "siloUID": "x"}]}`))
	if err := r.f.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	n, _ := r.cp.counts()
	if n != 1 || r.cp.reports[0].Silo != "" || r.cp.reports[0].SiloUID != "" {
		t.Fatalf("relayed %+v (the silo's own silo fields must not go through)", r.cp.reports)
	}
	if r.cp.reports[0].TTL != "10s" {
		t.Fatalf("no TTL given: the host gives one so a silo that stops answering goes stale, got %q", r.cp.reports[0].TTL)
	}
	// Unchanged: not relayed again until it would go stale.
	r.clk.Step(time.Second)
	_ = r.f.Fetch(t.Context())
	if n, _ := r.cp.counts(); n != 1 {
		t.Fatalf("unchanged report relayed again (%d)", n)
	}
	r.clk.Step(5 * time.Second)
	_ = r.f.Fetch(t.Context())
	if n, _ := r.cp.counts(); n != 2 {
		t.Fatalf("a report about to go stale wasn't refreshed (%d)", n)
	}
	// An HTML pane: its bundle is fetched once per digest, checked, relayed before its report.
	digest := panes.Digest([]byte(bundleHTML))
	r.serve(htmlPaneServer(digest, bundleHTML))
	for range 3 {
		r.clk.Step(time.Second)
		if err := r.f.Fetch(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, b := r.cp.counts(); b != 1 || string(r.cp.bundles[0]) != bundleHTML || r.hit("/panes/bundles/"+digest) != 1 {
		t.Fatalf("bundle relayed %d times, fetched %d", b, r.hit("/panes/bundles/"+digest))
	}
	if !strings.HasPrefix(r.states[len(r.states)-1], "Fetched") {
		t.Fatalf("state %v", r.states)
	}
}

// Hostile answers cut the silo off: nothing relayed, a reason, and its panes go stale.
func TestPaneFetchCutsOffHostileSilos(t *testing.T) {
	paneListTimeout, paneBundleTimeout = 300*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { paneListTimeout, paneBundleTimeout = 2*time.Second, 5*time.Second })
	digest := panes.Digest([]byte(bundleHTML))
	for name, c := range map[string]struct {
		cfg  *v1.PaneConfig
		h    http.HandlerFunc
		want string
	}{
		"huge": {on("status"), func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"panes": [{"pane": "a", "kind": "status", "message": "`+strings.Repeat("x", 300<<10)+`"}]}`)
		}, "more than"},
		"huge, declared": {on("status"), func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", strconv.Itoa(10<<20))
			_, _ = io.WriteString(w, "{")
		}, "bytes, at most"},
		"slow": {on("status"), func(w http.ResponseWriter, q *http.Request) {
			select {
			case <-q.Context().Done():
			case <-time.After(2 * time.Second):
			}
		}, "no answer within"},
		"slow body": {on("status"), func(w http.ResponseWriter, q *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"panes": [`)
			w.(http.Flusher).Flush()
			select {
			case <-q.Context().Done():
			case <-time.After(2 * time.Second):
			}
		}, "within"},
		"redirect": {on("status"), func(w http.ResponseWriter, q *http.Request) {
			http.Redirect(w, q, "http://203.0.113.1/elsewhere", http.StatusFound)
		}, "redirect"},
		"wrong content type": {on("status"), func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `{"panes": []}`)
		}, "Content-Type"},
		"not 200":       {on("status"), func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, "answered 500"},
		"unknown field": {on("status"), jsonList(`{"panes": [{"pane": "a", "kind": "status", "script": "x"}]}`), "isn't"},
		"too many panes": {on("status"), jsonList(`{"panes": [{"pane": "a", "kind": "status"}, {"pane": "b", "kind": "status"}, {"pane": "c", "kind": "status"}]}`),
			"3 panes, at most 2"},
		"same pane twice":  {on("status"), jsonList(`{"panes": [{"pane": "a", "kind": "status"}, {"pane": "a", "kind": "status"}]}`), "twice"},
		"kind not allowed": {on("status"), htmlPaneServer(digest, bundleHTML), "isn't allowed"},
		"bad report":       {on("status"), jsonList(`{"panes": [{"pane": "a", "kind": "status", "state": "pwned"}]}`), "state"},
		"digest mismatch":  {on("status", "html"), htmlPaneServer(digest, bundleHTML+"<script>evil()</script>"), "digest"},
		"huge bundle":      {on("status", "html"), htmlPaneServer(digest, strings.Repeat("x", v1.PaneBundleMaxBytes+1)), "more than"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newPaneRig(t, c.cfg)
			r.serve(c.h)
			err := r.f.Fetch(t.Context())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			if n, b := r.cp.counts(); n != 0 || b != 0 {
				t.Fatalf("relayed %d reports, %d bundles", n, b)
			}
			if st := r.states[len(r.states)-1]; !strings.HasPrefix(st, "CutOff: ") || !strings.Contains(st, "stale") {
				t.Fatalf("state %q", st)
			}
			if name == "redirect" && r.hit("/elsewhere") != 0 {
				t.Fatal("followed a redirect")
			}
		})
	}
}

func TestPaneFetchCutOffAndBack(t *testing.T) {
	r := newPaneRig(t, on("status"))
	r.serve(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Content-Type", "text/plain") })
	_ = r.f.Fetch(t.Context())
	if r.hit("/panes") != 1 {
		t.Fatal("not asked")
	}
	// Cut off: not asked at all for a minute.
	r.clk.Step(30 * time.Second)
	_ = r.f.Fetch(t.Context())
	if r.hit("/panes") != 1 {
		t.Fatal("asked while cut off")
	}
	r.clk.Step(31 * time.Second)
	_ = r.f.Fetch(t.Context()) // still wrong: two minutes now
	if r.hit("/panes") != 2 || !strings.Contains(r.states[len(r.states)-1], "2m0s") {
		t.Fatalf("hits %d, state %v", r.hit("/panes"), r.states)
	}
	r.serve(jsonList(`{"panes": [{"pane": "a", "kind": "status", "state": "idle"}]}`))
	r.clk.Step(2*time.Minute + time.Second)
	if err := r.f.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.cp.counts(); n != 1 || r.f.backoff != 0 {
		t.Fatalf("after a good answer: %d relayed, backoff %s", n, r.f.backoff)
	}
	// Too often: a silo whose reports change on every ask, faster than the rate, is cut off too.
	r.f.Limits = panes.Limits{MaxReport: 16 << 10, MaxData: 64 << 10, MaxBundle: v1.PaneBundleMaxBytes, Rate: 0.1, Burst: 1, MaxTTL: time.Hour}
	i := 0
	r.serve(func(w http.ResponseWriter, _ *http.Request) {
		i++
		jsonList(fmt.Sprintf(`{"panes": [{"pane": "a", "kind": "status", "message": "%d"}]}`, i))(w, nil)
	})
	var err error
	for range 3 {
		r.clk.Step(time.Second)
		if err = r.f.Fetch(t.Context()); err != nil {
			break
		}
	}
	if err == nil || !strings.Contains(err.Error(), "faster than") {
		t.Fatalf("too often: %v", err)
	}
}

// Nothing listening yet isn't held against a silo: no cut-off, Unreachable.
func TestPaneFetchUnreachable(t *testing.T) {
	r := newPaneRig(t, on("status"))
	r.f.Address = "127.0.0.1"
	r.f.Silo.Spec.Panes.HTTP.Port = 1
	if err := r.f.Fetch(t.Context()); err == nil {
		t.Fatal("no error")
	}
	if st := r.states[len(r.states)-1]; !strings.HasPrefix(st, "Unreachable") || !r.f.cutUntil.IsZero() {
		t.Fatalf("state %q, cut until %v", st, r.f.cutUntil)
	}
}
