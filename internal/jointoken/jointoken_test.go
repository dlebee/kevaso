package jointoken

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

func setup(t *testing.T) (*Issuer, *clock.Fake, context.Context) {
	clk := clock.NewFake(time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC))
	return &Issuer{Store: store.NewMemory(0), Clock: clk}, clk, context.Background()
}

func TestSingleUse(t *testing.T) {
	iss, _, ctx := setup(t)
	tok, err := iss.Create(ctx, "hv2", []string{"worker"}, time.Hour)
	if err != nil || !strings.HasPrefix(tok, "kvj_") {
		t.Fatalf("create: %q %v", tok, err)
	}
	if err := iss.Redeem(ctx, tok, "hv2", "worker"); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := iss.Redeem(ctx, tok, "hv2", "worker"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second use: want ErrInvalid, got %v", err)
	}
}

func TestRefusedAttemptDoesNotBurnTheToken(t *testing.T) {
	iss, _, ctx := setup(t)
	tok, _ := iss.Create(ctx, "hv2", []string{"worker"}, time.Hour)
	if err := iss.Redeem(ctx, tok, "hv9", "worker"); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("wrong host: %v", err)
	}
	if err := iss.Redeem(ctx, tok, "hv2", "control-plane"); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("wrong role: %v", err)
	}
	if err := iss.Redeem(ctx, tok, "hv2", "worker"); err != nil {
		t.Fatalf("right host and role after two refusals: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	iss, clk, ctx := setup(t)
	tok, _ := iss.Create(ctx, "hv2", []string{"worker"}, time.Hour)
	clk.Step(time.Hour)
	if err := iss.Redeem(ctx, tok, "hv2", "worker"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired token: want ErrInvalid, got %v", err)
	}
}

func TestForgedAndMalformed(t *testing.T) {
	iss, _, ctx := setup(t)
	tok, _ := iss.Create(ctx, "hv2", []string{"worker"}, time.Hour)
	id, _, _ := split(tok)
	for _, bad := range []string{"", "nope", "kvj_", "kvj_x", "kvj_" + id + ".wrongsecret", "kvj_unknown.secret", strings.TrimPrefix(tok, "kvj_")} {
		if err := iss.Redeem(ctx, bad, "hv2", "worker"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: want ErrInvalid, got %v", bad, err)
		}
	}
	// The real token still works: forgeries don't use it up.
	if err := iss.Redeem(ctx, tok, "hv2", "worker"); err != nil {
		t.Fatalf("real token after forgeries: %v", err)
	}
}

func TestOnlyAHashIsStored(t *testing.T) {
	iss, _, ctx := setup(t)
	tok, _ := iss.Create(ctx, "hv2", []string{"worker"}, time.Hour)
	_, secret, _ := split(tok)
	objs, _, _ := iss.Store.List(ctx, store.Selector{Kind: Kind})
	if len(objs) != 1 || strings.Contains(string(objs[0].Data), secret) {
		t.Fatalf("the secret is stored in clear: %s", objs[0].Data)
	}
}

func TestConcurrentRedeemsOneWins(t *testing.T) {
	iss, _, ctx := setup(t)
	tok, _ := iss.Create(ctx, "hv2", []string{"worker"}, time.Hour)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if iss.Redeem(ctx, tok, "hv2", "worker") == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent redeems succeeded, want exactly 1", wins)
	}
}

func TestCreateValidates(t *testing.T) {
	iss, _, ctx := setup(t)
	for _, tc := range []struct {
		host  string
		roles []string
		ttl   time.Duration
	}{{"", []string{"worker"}, time.Hour}, {"hv2", nil, time.Hour}, {"hv2", []string{"worker"}, 0}} {
		if _, err := iss.Create(ctx, tc.host, tc.roles, tc.ttl); err == nil {
			t.Errorf("create(%q, %v, %v) accepted", tc.host, tc.roles, tc.ttl)
		}
	}
}
