// Package jointoken issues and redeems one-time join tokens (research E019): `kvoadm` creates one for
// a host and the roles it may take, the host's agent presents it once with a CSR, and gets a
// certificate for that host and role only.
//
// Tokens look like kvj_<id>.<secret>. Only a hash of the secret is stored (in the store, under the
// internal kind JoinToken, which the API never serves). A token is single-use and expires; a
// refused attempt (wrong host, wrong role) doesn't burn it, so a typo doesn't force a new token.
package jointoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// Kind is the store kind tokens live under; never registered with the API.
const Kind = "JoinToken"

var (
	// ErrInvalid covers unknown, malformed, expired and used tokens alike: callers learn nothing
	// about which.
	ErrInvalid = errors.New("invalid join token")
	// ErrNotAllowed: the token is fine but doesn't allow this host or role (the token isn't used up).
	ErrNotAllowed = errors.New("join token doesn't allow this host or role")
)

type record struct {
	SecretHash string    `json:"secretHash"`
	Host       string    `json:"host"`
	Roles      []string  `json:"roles"`
	Expires    time.Time `json:"expires"`
	UsedAt     time.Time `json:"usedAt,omitempty"`
}

// Issuer creates and redeems tokens.
type Issuer struct {
	Store store.Store
	Clock clock.Clock
}

func hash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Create returns a new token allowing host to join with any of roles, valid for ttl.
func (i *Issuer) Create(ctx context.Context, host string, roles []string, ttl time.Duration) (string, error) {
	if host == "" || len(roles) == 0 || ttl <= 0 {
		return "", errors.New("join token needs a host, at least one role and a positive ttl")
	}
	id, secret := random(8), random(32)
	data, err := json.Marshal(record{
		SecretHash: hash(secret), Host: host, Roles: roles, Expires: i.Clock.Now().Add(ttl),
	})
	if err != nil {
		return "", err
	}
	if _, err := i.Store.Create(ctx, store.Key{Kind: Kind, Name: id}, data); err != nil {
		return "", err
	}
	return "kvj_" + id + "." + secret, nil
}

func split(token string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(token, "kvj_")
	if !found {
		return "", "", false
	}
	id, secret, ok = strings.Cut(rest, ".")
	return id, secret, ok && id != "" && secret != ""
}

// Redeem uses the token for host and role, exactly once.
func (i *Issuer) Redeem(ctx context.Context, token, host, role string) error {
	id, secret, ok := split(token)
	if !ok {
		return ErrInvalid
	}
	key := store.Key{Kind: Kind, Name: id}
	for attempt := 0; attempt < 5; attempt++ {
		o, err := i.Store.Get(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalid
		}
		if err != nil {
			return err
		}
		var r record
		if err := json.Unmarshal(o.Data, &r); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(hash(secret)), []byte(r.SecretHash)) != 1 ||
			!r.UsedAt.IsZero() || !i.Clock.Now().Before(r.Expires) {
			return ErrInvalid
		}
		if r.Host != host || !slices.Contains(r.Roles, role) {
			return fmt.Errorf("%w (token is for host %q)", ErrNotAllowed, r.Host)
		}
		r.UsedAt = i.Clock.Now()
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		// Conditional on the revision we read: two concurrent redeems can't both win.
		if _, err := i.Store.Update(ctx, key, data, o.Revision); errors.Is(err, store.ErrConflict) {
			continue
		} else if err != nil {
			return err
		}
		return nil
	}
	return ErrInvalid
}
