package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// K-076: a host cut off from its control plane keeps injecting a secret it was given only until
// the grant's own lifetime, an hour when the grant sets none (grants have no lifetime field
// today, so it is always the hour). After that every injection is refused with a clear error, and
// the gate logs it. A refusal from the control plane is never covered by what it gave before.

// brokerRig is a control plane answering the gate's injections: up answers the value, down
// isn't there (a cut-off host), refuse answers the broker's refusal, forbid a 403.
type brokerRig struct {
	mode  atomic.Value // "up", "down", "refuse", "forbid"
	calls atomic.Int32
	srv   *httptest.Server
}

func newBrokerRig(t *testing.T) *brokerRig {
	b := &brokerRig{}
	b.mode.Store("up")
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.calls.Add(1)
		switch b.mode.Load().(string) {
		case "down":
			// What a host cut off sees: the connection goes nowhere.
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			_ = c.Close()
		case "refuse":
			_ = json.NewEncoder(w).Encode(client.BrokerResponse{Error: "the grant no longer names this secret"})
		case "forbid":
			http.Error(w, `{"code":403,"reason":"Forbidden","message":"no"}`, http.StatusForbidden)
		default:
			_ = json.NewEncoder(w).Encode(client.BrokerResponse{Injections: []client.Injection{
				{Host: "api.allowed.test", Header: "Authorization", Value: "Bearer sk-1", Secret: "key"}}})
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

type fakeNow struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeNow) now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.t }
func (f *fakeNow) add(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

func injectRig(t *testing.T) (*egress, *brokerRig, *fakeNow, *[]string) {
	b := newBrokerRig(t)
	silo := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "claude-1", UID: "u1"}, Status: v1.SiloStatus{Host: "hv1"}}
	clock := &fakeNow{t: time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)}
	var mu sync.Mutex
	var logged []string
	e := &egress{c: client.New(b.srv.URL), hostName: "hv1", silos: func() []*v1.Silo { return []*v1.Silo{silo} },
		now: clock.now, log: func(f string, a ...any) {
			mu.Lock()
			logged = append(logged, fmt.Sprintf(f, a...))
			mu.Unlock()
		}}
	return e, b, clock, &logged
}

func TestTwoInjectionsForOneHostAreBothKept(t *testing.T) {
	b := &brokerRig{}
	b.mode.Store("up")
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(client.BrokerResponse{Injections: []client.Injection{
			{Host: "api.allowed.test", Header: "Authorization", Value: "Bearer sk-1", Secret: "key"},
			{Host: "api.allowed.test", Header: "X-Token", Value: "second", Secret: "other"},
		}})
	}))
	t.Cleanup(b.srv.Close)
	silo := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "claude-1", UID: "u1"}, Status: v1.SiloStatus{Host: "hv1"}}
	e := &egress{c: client.New(b.srv.URL), hostName: "hv1", silos: func() []*v1.Silo { return []*v1.Silo{silo} }}
	got, err := e.injections(context.Background(), "dev/claude-1")
	if err != nil {
		t.Fatal(err)
	}
	ins := got["api.allowed.test"]
	if len(ins) != 2 || ins[0].Header != "Authorization" || ins[0].Value != "Bearer sk-1" || ins[1].Header != "X-Token" || ins[1].Value != "second" {
		t.Fatalf("injections = %+v", ins)
	}
}

func TestACutOffHostInjectsForAnHourThenRefuses(t *testing.T) {
	e, b, clock, logged := injectRig(t)
	ctx := context.Background()
	if got, err := e.injections(ctx, "dev/claude-1"); err != nil || got["api.allowed.test"][0].Value != "Bearer sk-1" {
		t.Fatalf("connected: %v %v", got, err)
	}
	b.mode.Store("down")
	for _, after := range []time.Duration{2 * time.Minute, 30 * time.Minute, 59 * time.Minute} {
		clock.t = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC).Add(after)
		got, err := e.injections(ctx, "dev/claude-1")
		if err != nil || got["api.allowed.test"][0].Value != "Bearer sk-1" {
			t.Fatalf("cut off for %s: %v %v (the secret must be injected until the hour)", after, got, err)
		}
	}
	if !strings.Contains(strings.Join(*logged, "\n"), "for at most 1h0m0s") {
		t.Errorf("no log line that it injects from memory, and for how long: %q", *logged)
	}
	clock.add(time.Minute + time.Second) // 1h0m1s since the last answer
	_, err := e.injections(ctx, "dev/claude-1")
	if err == nil {
		t.Fatal("still injected after the hour")
	}
	for _, want := range []string{"1h0m0s", "control plane"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q doesn't say %q", err, want)
		}
	}
	// Back: injected at once from a fresh answer.
	b.mode.Store("up")
	if got, err := e.injections(ctx, "dev/claude-1"); err != nil || got["api.allowed.test"][0].Value != "Bearer sk-1" {
		t.Fatalf("reconnected: %v %v", got, err)
	}
}

// What the control plane refuses is refused at once: the value it gave before doesn't cover it.
func TestARefusalIsNeverCoveredByTheLastAnswer(t *testing.T) {
	for _, mode := range []string{"refuse", "forbid"} {
		e, b, clock, _ := injectRig(t)
		ctx := context.Background()
		if _, err := e.injections(ctx, "dev/claude-1"); err != nil {
			t.Fatal(err)
		}
		b.mode.Store(mode)
		clock.add(2 * time.Minute)
		if got, err := e.injections(ctx, "dev/claude-1"); err == nil {
			t.Errorf("%s: injected %v from the last answer", mode, got)
		}
		b.mode.Store("down") // and the refusal isn't undone by losing the control plane after it
		clock.add(2 * time.Minute)
		if got, err := e.injections(ctx, "dev/claude-1"); err == nil {
			t.Errorf("%s then cut off: injected %v", mode, got)
		}
	}
}
