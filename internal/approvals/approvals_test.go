package approvals

import (
	"errors"
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
	a := Name("claude-1", "uid-1", "get-secret", "gh")
	if a != Name("claude-1", "uid-1", "get-secret", "gh") {
		t.Fatal("same ask, different name")
	}
	for _, other := range []string{
		Name("claude-1", "uid-2", "get-secret", "gh"), // a new silo of the same name
		Name("claude-1", "uid-1", "sign", "gh"),
		Name("claude-1", "uid-1", "get-secret", "other"),
	} {
		if other == a {
			t.Fatalf("different asks share the name %s", a)
		}
	}
	if !strings.HasPrefix(a, "claude-1-") {
		t.Fatalf("name %q should start with the silo", a)
	}
	if n := Name(strings.Repeat("s", 80), "u", "sign", "k"); len(n) > 63 {
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
	ok, err := Answer(a, true, "alice", "", t0.Add(2*time.Minute))
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

func TestApprovalOfAnEarlierSiloDoesNothing(t *testing.T) {
	ok, _ := Answer(pending(), true, "alice", "", t0)
	c := call()
	c.SiloUID = "uid-2" // deleted and created again with the same name
	if out := Decide(c, ok, Limits{}, t0.Add(time.Minute)); out.Allow {
		t.Fatal("a new silo used the old silo's approval")
	}
}

func TestDeniedFailsThePollAndSaysWho(t *testing.T) {
	a := pending()
	no, err := Answer(a, false, "bob", "not during the freeze", t0.Add(time.Minute))
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
	if _, err := Answer(a, true, "alice", "", t0.Add(10*time.Minute)); !errors.Is(err, ErrTooLate) {
		t.Fatalf("late answer: %v", err)
	}
	if out := Decide(c, out.Store, Limits{}, t0.Add(11*time.Minute)); !errors.Is(out.Err, ErrExpired) || out.Store != nil {
		t.Fatalf("poll of an expired one = %+v", out)
	}
}

func TestAnswerOnlyOnce(t *testing.T) {
	ok, _ := Answer(pending(), true, "alice", "", t0)
	if _, err := Answer(ok, false, "mallory", "", t0); !errors.Is(err, ErrAnswered) {
		t.Fatalf("second answer: %v", err)
	}
}

func TestExpireSweep(t *testing.T) {
	old, fresh := pending(), pending()
	fresh.Spec.ExpiresAt = t0.Add(time.Hour)
	done, _ := Answer(pending(), true, "alice", "", t0)
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
