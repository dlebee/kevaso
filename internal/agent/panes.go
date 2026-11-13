package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/panes"
)

// Panes fetched by the host (design §10.1, ADR 0009). A silo that says where it answers
// (spec.panes.http) is asked, every spec.panes.every, from the host itself at the silo's own
// private address: GET PATH for its reports ({"panes": [...]}), and GET PATH/bundles/sha256:HEX
// once per HTML bundle. The request carries nothing (no parameters, identity or state), no
// redirect is followed, and what comes back is untrusted data: read within size and time limits,
// decoded strictly, checked with internal/panes, and relayed to the control plane only when it
// changed (or would go stale). A silo that answers too much, too slowly, too often or wrongly is
// cut off for a while (its panes go stale) and its Panes condition says why.

// Pane fetch limits (variables for tests).
var (
	paneListTimeout   = 2 * time.Second
	paneBundleTimeout = 5 * time.Second
	paneCutOffFirst   = time.Minute
	paneCutOffMax     = 15 * time.Minute
)

const paneReportSlack = 1 << 10

// errCutOff marks an answer that cuts the silo off; anything else (nothing listening yet) isn't
// held against it.
var errCutOff = errors.New("cut off")

type cutOff struct{ why string }

func (c cutOff) Error() string { return c.why }
func (c cutOff) Unwrap() error { return errCutOff }

func cut(f string, a ...any) error { return cutOff{fmt.Sprintf(f, a...)} }

// PaneFetcher fetches one silo's panes and relays them. Its fields are set once; Fetch and Run are
// one goroutine's.
type PaneFetcher struct {
	Client   *client.Client
	HostName string
	Silo     *v1.Silo // namespace, name, uid and spec.panes
	Address  string   // the silo's private address (no port)
	Clock    clock.Clock
	// Dial reaches the silo (nil: a plain dial from the host).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// OnState hears how it's going: ok, else the Panes condition's reason and message.
	OnState func(ok bool, reason, msg string)
	Limits  panes.Limits // zero: panes.Defaults

	bucket   panes.Bucket
	sent     map[string]sentPane // by pane name
	bundles  map[string]bool     // digests the control plane has from us
	cutUntil time.Time
	backoff  time.Duration
}

type sentPane struct {
	hash [32]byte
	at   time.Time
	ttl  time.Duration
}

func (f *PaneFetcher) limits() panes.Limits {
	if f.Limits == (panes.Limits{}) {
		return panes.Defaults
	}
	return f.Limits
}

func (f *PaneFetcher) now() time.Time {
	if f.Clock == nil {
		return time.Now()
	}
	return f.Clock.Now()
}

func (f *PaneFetcher) state(ok bool, reason, msg string) {
	if f.OnState != nil {
		f.OnState(ok, reason, msg)
	}
}

func (f *PaneFetcher) http() *http.Client {
	dial := f.Dial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	return &http.Client{
		Transport:     &http.Transport{DialContext: dial, DisableKeepAlives: true, Proxy: nil, MaxResponseHeaderBytes: 8 << 10},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// get fetches url, at most max bytes within limit, wanting one of types.
func (f *PaneFetcher) get(ctx context.Context, url string, max int64, limit time.Duration, types ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{"User-Agent": {"kevaso-panes"}, "Accept": {types[0]}}
	resp, err := f.http().Do(req)
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return nil, err // nothing listening (yet), or not reachable: not held against it
		}
		var ne net.Error
		if ctx.Err() != nil || (errors.As(err, &ne) && ne.Timeout()) {
			return nil, cut("no answer within %s", limit)
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, cut("answered a redirect (%d): none is followed", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, cut("answered %d", resp.StatusCode)
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	okType := false
	for _, t := range types {
		okType = okType || mt == t
	}
	if !okType {
		return nil, cut("answered Content-Type %q, want %s", resp.Header.Get("Content-Type"), types[0])
	}
	if resp.ContentLength > max {
		return nil, cut("answered %d bytes, at most %d", resp.ContentLength, max)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, cut("no full answer within %s", limit)
		}
		return nil, cut("answer cut short: %v", err)
	}
	if int64(len(b)) > max {
		return nil, cut("answered more than %d bytes", max)
	}
	return b, nil
}

func (f *PaneFetcher) base() string {
	cfg := f.Silo.Spec.Panes
	return "http://" + net.JoinHostPort(f.Address, strconv.Itoa(cfg.HTTP.Port)) + cfg.PanePath()
}

// Fetch asks once and relays what changed. While cut off it does nothing.
func (f *PaneFetcher) Fetch(ctx context.Context) error {
	now := f.now()
	if now.Before(f.cutUntil) {
		return nil
	}
	err := f.fetch(ctx)
	switch {
	case err == nil:
		f.backoff = 0
		f.state(true, "Fetched", "")
	case errors.Is(err, errCutOff):
		if f.backoff == 0 {
			f.backoff = paneCutOffFirst
		} else {
			f.backoff = min(2*f.backoff, paneCutOffMax)
		}
		f.cutUntil = f.now().Add(f.backoff)
		f.state(false, "CutOff", fmt.Sprintf("%v: not asked again for %s, its panes go stale", err, f.backoff))
	default:
		f.state(false, "Unreachable", fmt.Sprintf("%s: %v", f.base(), shortError(err)))
	}
	return err
}

func shortError(err error) string { return tail(err.Error(), 200) }

func (f *PaneFetcher) fetch(ctx context.Context) error {
	cfg, l := f.Silo.Spec.Panes, f.limits()
	maxPanes := panes.MaxPanes(cfg)
	body, err := f.get(ctx, f.base(), int64(maxPanes*(l.MaxReport+l.MaxData+paneReportSlack)), paneListTimeout, "application/json")
	if err != nil {
		return err
	}
	var list v1.PaneList
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil || dec.More() {
		return cut("the list isn't {\"panes\": [...]}: %v", err)
	}
	if len(list.Panes) > maxPanes {
		return cut("%d panes, at most %d (spec.panes.maxPanes)", len(list.Panes), maxPanes)
	}
	defTTL := max(3*panes.Every(cfg), 10*time.Second)
	var names []string
	seen := map[string]bool{}
	for i := range list.Panes {
		r := &list.Panes[i]
		r.Silo, r.SiloUID = "", ""
		if seen[r.Pane] {
			return cut("pane %q twice", r.Pane)
		}
		seen[r.Pane] = true
		if r.TTL == "" {
			r.TTL = min(defTTL, l.MaxTTL).String()
		}
		if err := panes.Check(cfg, *r, names, l); err != nil {
			return cut("pane %q: %v", r.Pane, err)
		}
		names = append(names, r.Pane)
	}
	if f.sent == nil {
		f.sent, f.bundles = map[string]sentPane{}, map[string]bool{}
	}
	for _, r := range list.Panes {
		b, _ := json.Marshal(r)
		h := sha256.Sum256(b)
		ttl, _ := time.ParseDuration(r.TTL)
		last, ok := f.sent[r.Pane]
		now := f.now()
		if ok && last.hash == h && now.Sub(last.at) < ttl/2 {
			continue // unchanged and not about to go stale
		}
		var bundle []byte
		if r.Kind == v1.PaneHTML && !f.bundles[r.Bundle] {
			bundle, err = f.get(ctx, f.base()+"/bundles/"+r.Bundle, int64(l.MaxBundle), paneBundleTimeout,
				"application/octet-stream", "application/x-tar", "text/html")
			if err != nil {
				return err
			}
			if err := panes.CheckBundle(r.Bundle, bundle, l); err != nil {
				return cut("bundle %s: %v", r.Bundle, err)
			}
		}
		if bundle != nil {
			if !f.take(now, l) {
				return cut("reports change faster than %g a second", l.Rate)
			}
			if err := f.relay(ctx, client.BrokerRequest{Op: client.OpPaneBundle, Payload: bundle}); err != nil {
				return err
			}
			f.bundles[r.Bundle] = true
		}
		if !f.take(now, l) {
			return cut("reports change faster than %g a second", l.Rate)
		}
		rep := r
		if err := f.relay(ctx, client.BrokerRequest{Op: client.OpPane, Pane: &rep}); err != nil {
			return err
		}
		f.sent[r.Pane] = sentPane{hash: h, at: now, ttl: ttl}
	}
	return nil
}

func (f *PaneFetcher) take(now time.Time, l panes.Limits) bool {
	b, ok := panes.Take(f.bucket, l, now)
	f.bucket = b
	return ok
}

// relay hands one report or bundle to the control plane, which checks it again.
func (f *PaneFetcher) relay(ctx context.Context, req client.BrokerRequest) error {
	s := f.Silo
	var resp client.BrokerResponse
	if err := f.Client.Call(ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
		Namespace: s.Namespace, Name: s.Name, UID: s.UID, Host: f.HostName, Request: req}, &resp); err != nil {
		return fmt.Errorf("the control plane: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("the control plane refused it: %s", resp.Error)
	}
	return nil
}

// Run fetches every spec.panes.every until ctx ends.
func (f *PaneFetcher) Run(ctx context.Context) {
	every := panes.Every(f.Silo.Spec.Panes)
	for {
		_ = f.Fetch(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// paneRun is a silo's running fetcher, and what it was started for.
type paneRun struct {
	key    string
	cancel context.CancelFunc
}

// paneKey is what restarts a silo's fetcher when it changes.
func paneKey(s *v1.Silo, address string) string {
	b, _ := json.Marshal(s.Spec.Panes)
	return s.UID + "|" + address + "|" + string(b)
}

// keepPanes runs the silo's pane fetcher while panes are on and it has an address; any other
// silo has none, and nothing is ever fetched from it.
func (a *Agent) keepPanes(ctx context.Context, s *v1.Silo, address string) {
	a.panesMu.Lock()
	defer a.panesMu.Unlock()
	cur, running := a.paneRuns.Load(s.UID)
	if !s.Spec.Panes.On() || address == "" {
		if running {
			cur.(paneRun).cancel()
			a.paneRuns.Delete(s.UID)
		}
		return
	}
	key := paneKey(s, address)
	if running && cur.(paneRun).key == key {
		return
	}
	if running {
		cur.(paneRun).cancel()
	}
	parent := a.runCtx
	if parent == nil {
		parent = context.WithoutCancel(ctx)
	}
	rctx, cancel := context.WithCancel(parent)
	a.paneRuns.Store(s.UID, paneRun{key: key, cancel: cancel})
	silo := &v1.Silo{TypeMeta: s.TypeMeta, ObjectMeta: s.ObjectMeta, Spec: s.Spec}
	var lastOK *bool
	f := &PaneFetcher{Client: a.Client, HostName: a.HostName, Silo: silo, Address: address, Clock: a.Clock, Dial: a.dial, // as the probes reach it
		OnState: func(ok bool, reason, msg string) {
			if lastOK != nil && *lastOK && ok {
				return // still fine: nothing to write
			}
			lastOK = &ok
			status := meta.ConditionTrue
			if !ok {
				status = meta.ConditionFalse
			}
			_ = a.setStatus(rctx, silo, func(st *v1.SiloStatus) {
				setCond(st, "Panes", status, reason, msg, silo.Generation, a.now())
			})
		}}
	go f.Run(rctx)
}

// stopPanes ends a silo's pane fetcher (it's gone from this host).
func (a *Agent) stopPanes(uid string) {
	a.panesMu.Lock()
	defer a.panesMu.Unlock()
	if cur, ok := a.paneRuns.Load(uid); ok {
		cur.(paneRun).cancel()
		a.paneRuns.Delete(uid)
	}
}
