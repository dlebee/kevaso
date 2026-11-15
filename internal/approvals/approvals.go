// Package approvals decides secret uses that need a person's yes (design §8.7). It's pure: the
// broker hands it the call and the silo's current Approval for that secret, and gets back what to
// do (let it through, keep waiting, fail) and what to store.
//
// The flow: a silo asks (get-secret, sign, or a request the gate would inject into). No active
// approval: a pending Approval is written, and the silo's helper polls it by name until someone
// answers or it expires. Approved: access lasts the time asked for, without asking again.
// Asking again (not polling) replaces a pending request, so there's never a pile of near-duplicates.
package approvals

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Limits come from the control plane's config.
type Limits struct {
	DefaultWait time.Duration // how long a request waits when the silo says nothing (10m)
	MaxWait     time.Duration // the longest any request waits (1h)
	DefaultFor  time.Duration // access once approved, when the silo asks for no time (15m)
	MaxFor      time.Duration // the longest access a silo may ask for (12h)
}

// WithDefaults fills what's unset.
func (l Limits) WithDefaults() Limits {
	if l.DefaultWait <= 0 {
		l.DefaultWait = 10 * time.Minute
	}
	if l.MaxWait <= 0 {
		l.MaxWait = time.Hour
	}
	if l.DefaultWait > l.MaxWait {
		l.DefaultWait = l.MaxWait
	}
	if l.DefaultFor <= 0 {
		l.DefaultFor = 15 * time.Minute
	}
	if l.MaxFor <= 0 {
		l.MaxFor = 12 * time.Hour
	}
	if l.DefaultFor > l.MaxFor {
		l.DefaultFor = l.MaxFor
	}
	return l
}

// Name is the Approval's name for a silo, a use and a secret: the same three always give the same
// name, which is how asking again replaces the pending request.
func Name(silo, siloUID, use, secret string) string {
	h := sha256.Sum256([]byte(siloUID + "\x00" + use + "\x00" + secret))
	if len(silo) > 54 {
		silo = silo[:54]
	}
	return silo + "-" + hex.EncodeToString(h[:4])
}

// State is where a silo stands with one secret.
type State int

const (
	None    State = iota // no request, or the approved access is over: ask
	Active               // approved and still within its time: go
	Pending              // asked, waiting for an answer
	Denied               // someone said no
	Expired              // nobody answered in time
)

func (s State) String() string {
	return [...]string{"None", "Active", "Pending", "Denied", "Expired"}[s]
}

// StateOf reads an existing approval for the silo with uid siloUID. An approval of an earlier silo
// of the same name counts as none.
func StateOf(a *v1.Approval, siloUID string, now time.Time) State {
	if a == nil || a.Spec.SiloUID != siloUID {
		return None
	}
	switch a.Status.Phase {
	case v1.ApprovalApproved:
		if a.Status.AccessUntil != nil && now.Before(*a.Status.AccessUntil) {
			return Active
		}
		return None
	case v1.ApprovalDenied:
		return Denied
	case v1.ApprovalExpired:
		return Expired
	default: // pending
		if now.Before(a.Spec.ExpiresAt) {
			return Pending
		}
		return Expired
	}
}

// Call is one use asking.
type Call struct {
	Namespace, Silo, SiloUID string
	Secret, Use, Grant       string
	For                      string // access wanted once approved ("" → the default)
	Wait                     string // how long to wait for an answer ("" → the default)
	Poll                     string // the approval this call is waiting on; "" for a new ask
	Destination              *v1.ApprovalDestination
	PayloadHash, Summary     string
}

// Outcome is what the broker does.
type Outcome struct {
	Allow bool         // go ahead: the approved access is active
	Wait  *v1.Approval // keep waiting on this one (pending)
	Err   error        // fail the call (denied, expired, a bad ask)
	// Store, when set, is written (a new or replacing request, or a request marked expired).
	Store *v1.Approval
}

// Errors the silo sees, so it can say which.
var (
	ErrDenied  = errors.New("denied")
	ErrExpired = errors.New("expired: nobody answered in time")
)

// Decide answers one call, given the silo's current approval for this use and secret (nil: none).
func Decide(c Call, existing *v1.Approval, l Limits, now time.Time) Outcome {
	l = l.WithDefaults()
	st := StateOf(existing, c.SiloUID, now)
	if st == Active {
		return Outcome{Allow: true}
	}
	if c.Poll != "" && existing != nil && existing.Name == c.Poll && existing.Spec.SiloUID == c.SiloUID {
		switch st {
		case Pending:
			return Outcome{Wait: existing}
		case Denied:
			err := fmt.Errorf("%w by %s", ErrDenied, existing.Status.AnsweredBy)
			if existing.Status.Reason != "" {
				err = fmt.Errorf("%w: %s", err, existing.Status.Reason)
			}
			return Outcome{Err: err}
		case Expired:
			out := Outcome{Err: ErrExpired}
			if existing.Status.Phase == v1.ApprovalPending || existing.Status.Phase == "" {
				out.Store = expire(existing)
			}
			return out
		}
		// None: the access it was waiting for came and went; ask again.
	}
	a, err := newRequest(c, l, now)
	if err != nil {
		return Outcome{Err: err}
	}
	return Outcome{Wait: a, Store: a}
}

func newRequest(c Call, l Limits, now time.Time) (*v1.Approval, error) {
	wait, err := within(c.Wait, l.DefaultWait, l.MaxWait, "wait")
	if err != nil {
		return nil, err
	}
	access, err := within(c.For, l.DefaultFor, l.MaxFor, "access")
	if err != nil {
		return nil, err
	}
	return &v1.Approval{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Approval"},
		ObjectMeta: meta.ObjectMeta{Namespace: c.Namespace, Name: Name(c.Silo, c.SiloUID, c.Use, c.Secret)},
		Spec: v1.ApprovalSpec{
			Silo: c.Silo, SiloUID: c.SiloUID, Secret: c.Secret, Use: c.Use, Grant: c.Grant,
			Destination: c.Destination, PayloadHash: c.PayloadHash, Summary: c.Summary,
			For: access.String(), RequestedAt: now, ExpiresAt: now.Add(wait),
		},
		Status: v1.ApprovalStatus{Phase: v1.ApprovalPending},
	}, nil
}

// within parses a duration, defaulting "" and refusing more than max (or less than a second).
func within(s string, def, max time.Duration, what string) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s %q: %v", what, s, err)
	}
	if d < time.Second {
		return 0, fmt.Errorf("%s %s: at least 1s", what, s)
	}
	if d > max {
		return 0, fmt.Errorf("%s %s is more than this cluster allows (%s)", what, d, max)
	}
	return d, nil
}

func expire(a *v1.Approval) *v1.Approval {
	c := *a
	c.Status = v1.ApprovalStatus{Phase: v1.ApprovalExpired}
	return &c
}

// RequestID names what a request asks for: its silo, secret or port, use, grant, destination,
// payload and the access wanted, as the full SHA-256 of all of it (64 hex digits). A request asked
// again with anything different has another ID (when it was asked, and until when it waits, are
// not part of it). A person's answer carries the ID of the request they read, so a yes is for
// exactly that (K-017), and it is compared in full: never a prefix (K-059). ShortID is for people
// to read.
func RequestID(a *v1.Approval) string {
	sp := a.Spec
	b, _ := json.Marshal([]any{sp.Silo, sp.SiloUID, sp.Secret, sp.Port, sp.Use, sp.Grant, sp.Destination, sp.PayloadHash, sp.Summary, sp.For})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Lengths, in hex digits: a full RequestID, what is shown to people, and the least a person may
// type for kvo to find the full one.
const (
	IDLen     = 64
	ShortLen  = 32
	MinPrefix = 32
)

// ShortID is the start of a RequestID, for display only. It is never what an answer is compared to.
func ShortID(id string) string {
	if len(id) > ShortLen {
		return id[:ShortLen]
	}
	return id
}

// ResolveRequest turns what a person typed for --request into a full RequestID, for the pending
// approval a (the one they named): a full ID is checked for form and returned; a prefix of at
// least MinPrefix digits is completed from a's current ID, only if it is that one's. The full ID
// is what gets sent and compared; this only saves typing.
func ResolveRequest(typed string, a *v1.Approval) (string, error) {
	typed = strings.ToLower(strings.TrimSpace(typed))
	if _, err := hex.DecodeString(typed); err != nil || typed == "" {
		return "", fmt.Errorf("request %q: not a request ID (hex digits, from kvo get approvals)", typed)
	}
	if len(typed) == IDLen {
		return typed, nil
	}
	if len(typed) < MinPrefix {
		return "", fmt.Errorf("request %q: too short, give at least %d digits of the REQUEST column", typed, MinPrefix)
	}
	if a.Status.Phase != v1.ApprovalPending && a.Status.Phase != "" {
		return "", fmt.Errorf("approval %s: %w (%s)", a.Name, ErrAnswered, a.Status.Phase)
	}
	id := RequestID(a)
	if !strings.HasPrefix(id, typed) {
		return "", fmt.Errorf("approval %s: %w: no pending request starts with %s (it is %s now)", a.Name, ErrChanged, typed, ShortID(id))
	}
	return id, nil
}

// Answer errors.
var (
	ErrAnswered = errors.New("already answered")
	ErrTooLate  = errors.New("expired before the answer")
	ErrChanged  = errors.New("the request changed since it was read")
	ErrWhich    = errors.New("a yes must say which request it is for")
)

// Answer records a person's yes or no to the request they read, request being its RequestID. A
// yes needs it; a request asked again with anything else since is not answered (ErrChanged). It
// returns the approval to store; on ErrTooLate that's the request marked expired (store it too).
func Answer(a *v1.Approval, approve bool, request, who, reason string, now time.Time) (*v1.Approval, error) {
	if a.Status.Phase != v1.ApprovalPending && a.Status.Phase != "" {
		return nil, fmt.Errorf("approval %s: %w (%s by %s)", a.Name, ErrAnswered, a.Status.Phase, a.Status.AnsweredBy)
	}
	switch id := RequestID(a); {
	case request == "" && approve:
		return nil, fmt.Errorf("approval %s: %w (request %s: %s, for %s)", a.Name, ErrWhich, id, a.Spec.Summary, a.Spec.For)
	case request != "" && len(request) != IDLen:
		// Never a prefix: a short form can be made to match two different requests.
		return nil, fmt.Errorf("approval %s: %w: the request is its full %d-digit ID, not %q", a.Name, ErrWhich, IDLen, request)
	case request != "" && subtle.ConstantTimeCompare([]byte(strings.ToLower(request)), []byte(id)) != 1:
		return nil, fmt.Errorf("approval %s: %w: it is request %s now (%s, for %s); read it again and answer that one", a.Name, ErrChanged, ShortID(id), a.Spec.Summary, a.Spec.For)
	}
	if !now.Before(a.Spec.ExpiresAt) {
		return expire(a), fmt.Errorf("approval %s: %w", a.Name, ErrTooLate)
	}
	out := *a
	at := now
	out.Status = v1.ApprovalStatus{AnsweredBy: who, AnsweredAt: &at, Reason: reason}
	if !approve {
		out.Status.Phase = v1.ApprovalDenied
		return &out, nil
	}
	access, err := time.ParseDuration(a.Spec.For)
	if err != nil || access <= 0 {
		return nil, fmt.Errorf("approval %s: bad spec.for %q", a.Name, a.Spec.For)
	}
	until := now.Add(access)
	out.Status.Phase, out.Status.AccessUntil = v1.ApprovalApproved, &until
	return &out, nil
}

// Expire returns the pending approvals that ran out unanswered, marked expired (to store).
func Expire(all []*v1.Approval, now time.Time) []*v1.Approval {
	var out []*v1.Approval
	for _, a := range all {
		if (a.Status.Phase == v1.ApprovalPending || a.Status.Phase == "") && !now.Before(a.Spec.ExpiresAt) {
			out = append(out, expire(a))
		}
	}
	return out
}

// MayAnswer reports whether this kind of caller can ever answer an approval: people only. A
// service account's token (CI, a script, an agent) never can, and neither can a host or a silo.
func MayAnswer(identityType string) bool {
	return identityType == "user"
}
