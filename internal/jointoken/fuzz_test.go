package jointoken

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// FuzzRedeem: whatever a stranger at /enroll presents as a token, for whatever host and role,
// only the real token, for its host and one of its roles, is ever accepted; anything else is
// refused without telling which part was wrong (ErrInvalid), unless the token itself is right.
//
//	go test ./internal/jointoken -run '^$' -fuzz FuzzRedeem -fuzztime 60s
func FuzzRedeem(f *testing.F) {
	ctx := context.Background()
	clk := clock.NewFake(time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC))
	iss := &Issuer{Store: store.NewMemory(0), Clock: clk}
	real, err := iss.Create(ctx, "hv2", []string{"worker"}, time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	id, secret, _ := split(real)
	for _, s := range []string{real, "kvj_" + id + "." + secret[:len(secret)-1], "kvj_" + id + ".", "kvj_." + secret, "kvj_" + id,
		strings.ToUpper(real), real + "x", " " + real, "kvj_" + id + "." + secret + "." + secret, "kvj_../" + id + "." + secret, "kvj_" + id + "/." + secret, ""} {
		f.Add(s, "hv2", "worker")
	}
	f.Add(real, "hv9", "worker")
	f.Add(real, "hv2", "control-plane")
	f.Fuzz(func(t *testing.T, token, host, role string) {
		right := token == real
		err := iss.Check(ctx, token, host, role)
		switch {
		case err == nil && (!right || host != "hv2" || role != "worker"):
			t.Fatalf("Check accepted %q for %q/%q", token, host, role)
		case errors.Is(err, ErrNotAllowed) && !right:
			t.Fatalf("%q isn't the token, yet the answer says it is (%v)", token, err)
		case err != nil && !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrNotAllowed):
			t.Fatalf("%q: %v", token, err)
		}
		if right {
			return // Redeem would spend it: the seeds cover that
		}
		if err := iss.Redeem(ctx, token, host, role); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Redeem %q: %v, want ErrInvalid", token, err)
		}
	})
}
