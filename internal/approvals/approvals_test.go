package approvals

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
)

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func call() Call {
	return Call{Namespace: "agents", Silo: "claude-1", SiloUID: "uid-1", Secret: "github-admin", Use: v1.ApprovalForSecret, Grant: "dangerous"}
}

func TestNameIsStablePerSiloUseAndSecret(t *testing.T) {
	a := Name("claude-1", "uid-1", "get-secret", "gh", "sec-1")
	if a != Name("claude-1", "uid-1", "get-secret", "gh", "sec-1") {
		t.Fatal("same ask, different name")
	}
	for _, other := range []string{
		Name("claude-1", "uid-2", "get-secret", "gh", "sec-1"), // a new silo of the same name
		Name("claude-1", "uid-1", "sign", "gh", "sec-1"),
		Name("claude-1", "uid-1", "get-secret", "other", "sec-1"),
		Name("claude-1", "uid-1", "get-secret", "gh", "sec-2"), // the secret deleted and created again
	} {
		if other == a {
			t.Fatalf("different asks share the name %s", a)
		}
	}
	if !strings.HasPrefix(a, "claude-1-") {
		t.Fatalf("name %q should start with the silo", a)
	}
	if n := Name(strings.Repeat("s", 80), "u", "sign", "k", "sec"); len(n) > 63 {
		t.Fatalf("name is %d characters", len(n))
	}
}

func TestFirstAskWritesAPendingRequestThatExpires(t *testing.T) {
	c := call()
	c.For = "30m"
	out := Decide(c, nil, Limits{}, t0)
	if out.Allow || out.Err != nil || out.Wait == nil || out.Store != out.Wait {
		t.Fatalf("first ask = %+v", out)
	}
	a := out.Store
	if a.Status.Phase != v1.ApprovalPending || a.Spec.For != "30m0s" || a.Spec.Grant != "dangerous" {
		t.Fatalf("request = %+v", a)
	}
	if !a.Spec.ExpiresAt.Equal(t0.Add(10 * time.Minute)) {
		t.Fatalf("expires at %s, want the default wait", a.Spec.ExpiresAt)
	}
}

func TestLimits(t *testing.T) {
	l := Limits{MaxWait: 5 * time.Minute, MaxFor: time.Hour}
	for name, c := range map[string]func(*Call){
		"too long access": func(c *Call) { c.For = "2h" },
		"too long wait":   func(c *Call) { c.Wait = "6m" },
		"not a duration":  func(c *Call) { c.For = "forever" },
		"under a second":  func(c *Call) { c.For = "1ms" },
	} {
		cl := call()
		c(&cl)
		if out := Decide(cl, nil, l, t0); out.Err == nil || out.Store != nil {
			t.Errorf("%s: %+v, want an error and nothing stored", name, out)
		}
	}
	// The defaults never exceed the maximums.
	out := Decide(call(), nil, l, t0)
	if !out.Store.Spec.ExpiresAt.Equal(t0.Add(5*time.Minute)) || out.Store.Spec.For != "15m0s" {
		t.Fatalf("defaults under limits: %+v", out.Store.Spec)
	}
	if d := (Limits{MaxFor: time.Minute}).WithDefaults(); d.DefaultFor != time.Minute {
		t.Fatalf("DefaultFor %s above MaxFor", d.DefaultFor)
	}
}

func pending() *v1.Approval {
	return Decide(call(), nil, Limits{}, t0).Store
}

func TestPollingWaitsWithoutReplacing(t *testing.T) {
	a := pending()
	c := call()
	c.Poll = a.Name
	out := Decide(c, a, Limits{}, t0.Add(time.Minute))
	if out.Wait != a || out.Store != nil || out.Allow {
		t.Fatalf("poll of a pending request = %+v, want wait and nothing written", out)
	}
}

func TestAskingAgainReplacesThePendingRequest(t *testing.T) {
	a := pending()
	c := call()
	c.For = "5m"
	out := Decide(c, a, Limits{}, t0.Add(3*time.Minute))
	if out.Store == nil || out.Store.Name != a.Name {
		t.Fatalf("re-ask = %+v, want the same approval replaced", out)
	}
	if out.Store.Spec.For != "5m0s" || !out.Store.Spec.ExpiresAt.Equal(t0.Add(13*time.Minute)) {
		t.Fatalf("replacement keeps old details: %+v", out.Store.Spec)
	}
}

func TestApprovedAccessLastsItsTime(t *testing.T) {
	a := pending()
	ok, err := Answer(a, true, RequestID(a), "alice", "", t0.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ok.Status.Phase != v1.ApprovalApproved || ok.Status.AnsweredBy != "alice" || !ok.Status.AccessUntil.Equal(t0.Add(17*time.Minute)) {
		t.Fatalf("approved = %+v", ok.Status)
	}
	if a.Status.Phase != v1.ApprovalPending {
		t.Fatal("Answer changed its input")
	}
	for _, c := range []Call{call(), func() Call { c := call(); c.Poll = a.Name; return c }()} {
		if out := Decide(c, ok, Limits{}, t0.Add(16*time.Minute)); !out.Allow || out.Store != nil {
			t.Fatalf("within access: %+v", out)
		}
	}
	// Access over: the next use asks again.
	out := Decide(call(), ok, Limits{}, t0.Add(17*time.Minute))
	if out.Allow || out.Store == nil || out.Store.Status.Phase != v1.ApprovalPending {
		t.Fatalf("after access = %+v, want a new request", out)
	}
	c := call()
	c.Poll = a.Name
	if out := Decide(c, ok, Limits{}, t0.Add(20*time.Minute)); out.Store == nil {
		t.Fatal("a poll after the access ended should ask again")
	}
}

func TestApprovalOfARecreatedSecretDoesNothing(t *testing.T) {
	c := call()
	c.SecretUID = "sec-1"
	p := Decide(c, nil, Limits{}, t0).Store
	ok, err := Answer(p, true, RequestID(p), "alice", "", t0)
	if err != nil {
		t.Fatal(err)
	}
	again := call()
	again.SecretUID = "sec-2" // the secret was deleted and created again
	if out := Decide(again, ok, Limits{}, t0.Add(time.Minute)); out.Allow {
		t.Fatal("a new secret used the old secret's approval")
	}
	if Name(c.Silo, c.SiloUID, c.Use, c.Secret, "sec-1") == Name(c.Silo, c.SiloUID, c.Use, c.Secret, "sec-2") {
		t.Fatal("the two secrets share an approval name")
	}
}

func TestApprovalOfAnEarlierSiloDoesNothing(t *testing.T) {
	p := pending()
	ok, _ := Answer(p, true, RequestID(p), "alice", "", t0)
	c := call()
	c.SiloUID = "uid-2" // deleted and created again with the same name
	if out := Decide(c, ok, Limits{}, t0.Add(time.Minute)); out.Allow {
		t.Fatal("a new silo used the old silo's approval")
	}
}

func TestDeniedFailsThePollAndSaysWho(t *testing.T) {
	a := pending()
	no, err := Answer(a, false, RequestID(a), "bob", "not during the freeze", t0.Add(time.Minute))
	if err != nil || no.Status.Phase != v1.ApprovalDenied || no.Status.AccessUntil != nil {
		t.Fatalf("deny = %+v, %v", no, err)
	}
	c := call()
	c.Poll = a.Name
	out := Decide(c, no, Limits{}, t0.Add(2*time.Minute))
	if !errors.Is(out.Err, ErrDenied) || !strings.Contains(out.Err.Error(), "bob") || !strings.Contains(out.Err.Error(), "freeze") || out.Allow {
		t.Fatalf("poll after deny = %+v", out)
	}
	// A fresh ask after a no is a new request (the person may change their mind later).
	if out := Decide(call(), no, Limits{}, t0.Add(3*time.Minute)); out.Store == nil || out.Store.Status.Phase != v1.ApprovalPending {
		t.Fatalf("new ask after deny = %+v", out)
	}
}

func TestUnansweredExpires(t *testing.T) {
	a := pending()
	c := call()
	c.Poll = a.Name
	out := Decide(c, a, Limits{}, t0.Add(10*time.Minute))
	if !errors.Is(out.Err, ErrExpired) || out.Store == nil || out.Store.Status.Phase != v1.ApprovalExpired {
		t.Fatalf("poll at expiry = %+v", out)
	}
	if _, err := Answer(a, true, RequestID(a), "alice", "", t0.Add(10*time.Minute)); !errors.Is(err, ErrTooLate) {
		t.Fatalf("late answer: %v", err)
	}
	if out := Decide(c, out.Store, Limits{}, t0.Add(11*time.Minute)); !errors.Is(out.Err, ErrExpired) || out.Store != nil {
		t.Fatalf("poll of an expired one = %+v", out)
	}
}

func TestAnswerOnlyOnce(t *testing.T) {
	p := pending()
	ok, _ := Answer(p, true, RequestID(p), "alice", "", t0)
	if _, err := Answer(ok, false, RequestID(ok), "mallory", "", t0); !errors.Is(err, ErrAnswered) {
		t.Fatalf("second answer: %v", err)
	}
}

func TestExpireSweep(t *testing.T) {
	old, fresh := pending(), pending()
	p := pending()
	fresh.Spec.ExpiresAt = t0.Add(time.Hour)
	done, _ := Answer(p, true, RequestID(p), "alice", "", t0)
	got := Expire([]*v1.Approval{old, fresh, done}, t0.Add(10*time.Minute))
	if len(got) != 1 || got[0].Status.Phase != v1.ApprovalExpired || old.Status.Phase != v1.ApprovalPending {
		t.Fatalf("Expire = %+v", got)
	}
}

func TestOnlyPeopleAnswer(t *testing.T) {
	for typ, want := range map[string]bool{"user": true, "serviceaccount": false, "host": false, "component": false, "silo": false, "": false} {
		if MayAnswer(typ) != want {
			t.Errorf("MayAnswer(%q) = %v", typ, !want)
		}
	}
}

func TestStateNames(t *testing.T) {
	if Pending.String() != "Pending" || Active.String() != "Active" {
		t.Fatal(Pending.String())
	}
}

// K-017, in the package: a yes names the request it is for, and a request asked again with
// anything else is another request.
func TestK017AnswerIsBoundToTheRequest(t *testing.T) {
	c := Call{Namespace: "dev", Silo: "s", SiloUID: "u1", Secret: "key", Use: v1.ApprovalForSign, Grant: "g", For: "1m", PayloadHash: "aaaa", Summary: "sign 32 bytes"}
	first := Decide(c, nil, Limits{}, t0).Store
	read := RequestID(first)
	c.For, c.PayloadHash = "12h", "bbbb"
	second := Decide(c, first, Limits{}, t0.Add(time.Second)).Store
	if second.Name != first.Name || RequestID(second) == read {
		t.Fatalf("asked again: same name %v, same request %v", second.Name == first.Name, RequestID(second) == read)
	}
	if _, err := Answer(second, true, read, "alice", "", t0.Add(2*time.Second)); !errors.Is(err, ErrChanged) {
		t.Fatalf("a yes for what was read, on the changed request: %v", err)
	}
	if _, err := Answer(second, true, "", "alice", "", t0.Add(2*time.Second)); !errors.Is(err, ErrWhich) {
		t.Fatalf("a yes for no request in particular: %v", err)
	}
	// Only when it was asked and until when it waits: the same request.
	c2 := c
	c2.Wait = "5m"
	again := Decide(c2, second, Limits{}, t0.Add(3*time.Second)).Store
	if RequestID(again) != RequestID(second) {
		t.Fatal("asking again with only another wait changed the request")
	}
	if a, err := Answer(second, true, RequestID(second), "alice", "", t0.Add(2*time.Second)); err != nil || a.Status.Phase != v1.ApprovalApproved {
		t.Fatalf("a yes for the request as it is: %v", err)
	}
}

// collidingAsks are two requests of one silo, "1 minute" and "12 hours", whose IDs agreed in their
// first 48 bits (found by a birthday search over the payload hash: the old ID was that many bits).
// The silo chooses the payload, so this is within its reach (K-059).
func collidingAsks() (short, long Call) {
	c := Call{Namespace: "dev", Silo: "s", SiloUID: "u1", Secret: "key", Use: v1.ApprovalForSign, Grant: "g", Summary: "sign 32 bytes"}
	short, long = c, c
	short.For, short.PayloadHash = "1m", fmt.Sprintf("%016x", 0x12a00be)
	long.For, long.PayloadHash = "12h", fmt.Sprintf("%016x", 0xd1d704)
	return short, long
}

// K-059: the guard is the whole digest. A person read the short request; the silo asked again with
// the long one, same short form; a yes carrying the short form, or the first request's ID, is not a
// yes to the second.
func TestK059CollidingShortIDsAreNotTheSameRequest(t *testing.T) {
	cs, cl := collidingAsks()
	first := Decide(cs, nil, Limits{}, t0).Store
	second := Decide(cl, first, Limits{}, t0.Add(time.Second)).Store
	if second.Name != first.Name || second.Spec.For == first.Spec.For {
		t.Fatalf("the second ask must replace the first: names %s/%s, for %s/%s", first.Name, second.Name, first.Spec.For, second.Spec.For)
	}
	idFirst, idSecond := RequestID(first), RequestID(second)
	if len(idFirst) != 64 || len(idSecond) != 64 {
		t.Errorf("a request ID is the full SHA-256: %d and %d digits", len(idFirst), len(idSecond))
	}
	if idFirst == idSecond {
		t.Fatal("two different requests have one ID")
	}
	// The scenario: these two agree in their first 48 bits (what the old ID was).
	if idFirst[:12] != idSecond[:12] {
		t.Fatalf("the test's pair no longer collides in 48 bits: %s %s", idFirst[:12], idSecond[:12])
	}
	for name, id := range map[string]string{
		"the 48-bit form the person could have read": idFirst[:12],
		"the first request's full ID":                idFirst,
		"a prefix of the second's own ID":            cut(idSecond, 32),
		"the second's ID cut by one digit":           cut(idSecond, 63),
		"the second's ID with a digit added":         idSecond + "0",
	} {
		if a, err := Answer(second, true, id, "alice", "", t0.Add(2*time.Second)); err == nil {
			t.Errorf("%s was accepted: %s approved for %s", name, a.Status.Phase, a.Spec.For)
		}
	}
	if a, err := Answer(second, true, idSecond, "alice", "", t0.Add(2*time.Second)); err != nil || a.Status.Phase != v1.ApprovalApproved {
		t.Fatalf("a yes with the full ID of the request as it is: %v", err)
	}
	if a, err := Answer(second, true, strings.ToUpper(idSecond), "alice", "", t0.Add(2*time.Second)); err != nil || a.Status.Phase != v1.ApprovalApproved {
		t.Fatalf("the same ID in capitals: %v", err)
	}
	// A no may name no request, but one it names is held to the same rule.
	if _, err := Answer(second, false, idFirst[:12], "alice", "", t0.Add(2*time.Second)); err == nil {
		t.Error("a no naming a short form was accepted")
	}
	if _, err := Answer(second, false, "", "alice", "", t0.Add(2*time.Second)); err != nil {
		t.Errorf("a no naming nothing: %v", err)
	}
}

func cut(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
