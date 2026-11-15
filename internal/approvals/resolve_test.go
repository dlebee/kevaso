package approvals

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// ShortID is for reading; ResolveRequest completes a typed prefix only from the one request named,
// and only when it is pending and the prefix is long enough and its own.
func TestResolveRequestIsForTypingOnly(t *testing.T) {
	cs, cl := collidingAsks()
	first := Decide(cs, nil, Limits{}, t0).Store
	second := Decide(cl, first, Limits{}, t0.Add(time.Second)).Store
	id := RequestID(second)
	if got := ShortID(id); len(got) != ShortLen || !strings.HasPrefix(id, got) {
		t.Fatalf("short id %q", got)
	}
	for _, ok := range []string{id, id[:ShortLen], id[:MinPrefix], strings.ToUpper(id[:MinPrefix+4])} {
		if got, err := ResolveRequest(ok, second); err != nil || got != id {
			t.Errorf("%q resolved to %q, %v", ok, got, err)
		}
	}
	for name, typed := range map[string]string{
		"too short":         id[:MinPrefix-1],
		"not hex":           strings.Repeat("z", MinPrefix),
		"empty":             "",
		"another request":   RequestID(first)[:MinPrefix],
		"the other's start": strings.Repeat("0", MinPrefix),
	} {
		if got, err := ResolveRequest(typed, second); err == nil {
			t.Errorf("%s: %q resolved to %q", name, typed, got)
		}
	}
	// The collision does not help: the prefix both share resolves to the request as it is now,
	// whichever one the person read, so the full ID that gets sent is the current one's. What a
	// person may have read is a request at least ShortLen digits long.
	ans, _ := Answer(second, true, id, "alice", "", t0.Add(3*time.Second))
	if _, err := ResolveRequest(id[:ShortLen], ans); !errors.Is(err, ErrAnswered) {
		t.Errorf("an answered request: %v", err)
	}
}
