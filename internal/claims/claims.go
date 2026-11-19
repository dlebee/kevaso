// Package claims makes a value unique across the cluster by the store, not by a cache: one store
// record per value in a pool (a Service cluster IP, a node port, a host port on one host), created
// only if absent. Two controllers that pick the same value from caches that are behind (two
// workers, or an old leader and a new one) cannot both have it: the second Take fails and that
// controller picks another value.
//
// A claim names its holder (kind, namespace, name, UID) and the holder's version the claim was
// written against (the version its own write of the value is conditional on). A claim whose holder
// is gone, or that its holder no longer uses, is taken over; "no longer uses" is judged only once
// the holder has been written since the claim, so a holder that has claimed but not written yet is
// never robbed. Everything is read from the store itself.
package claims

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"kevaso.com/core/internal/store"
)

// Kind is the store kind claims are kept under (the control plane's own, not an API kind).
const Kind = "UniqueClaim"

// Holder is who holds a claim.
type Holder struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	// Version is the holder's resourceVersion the claim was made against.
	Version string `json:"version"`
}

// Uses reports whether the holder object, as stored (its JSON), still uses value. Every caller of
// one pool passes the same function.
type Uses func(obj []byte, value string) bool

// Claims takes and lets go of claims in a store.
type Claims struct {
	Store store.Store
}

// ErrBusy: the claim kept changing under us; try again later.
var ErrBusy = errors.New("claim kept changing")

func key(pool, value string) store.Key { return store.Key{Kind: Kind, Namespace: pool, Name: value} }

// Take claims value in pool for h. It reports false when someone else holds it (pick another).
// Taking a value h already holds succeeds, and records h.Version as the write it is for. Take
// before the write that uses the value, with the version that write is conditional on.
func (c *Claims) Take(ctx context.Context, pool, value string, h Holder, uses Uses) (bool, error) {
	data, err := json.Marshal(h)
	if err != nil {
		return false, err
	}
	k := key(pool, value)
	for range 4 {
		_, err := c.Store.Create(ctx, k, data)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, store.ErrExists) {
			return false, err
		}
		cur, err := c.Store.Get(ctx, k)
		if errors.Is(err, store.ErrNotFound) {
			continue // let go meanwhile: try again
		}
		if err != nil {
			return false, err
		}
		var other Holder
		if err := json.Unmarshal(cur.Data, &other); err != nil {
			return false, fmt.Errorf("claim %s: %w", k, err)
		}
		if other.UID == h.UID {
			if other.Version == h.Version {
				return true, nil
			}
			// Ours, made against an older version: say which write it is for now, or a holder
			// written since (by anyone) would look as if it had stopped using it.
			if _, err := c.Store.Update(ctx, k, data, cur.Revision); err == nil {
				return true, nil
			} else if !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
				return false, err
			}
			continue
		}
		held, err := c.holds(ctx, other, value, uses)
		if err != nil || held {
			return false, err
		}
		// Stale: its holder is gone or uses something else now. Take it over, conditionally on
		// the claim being the one judged.
		if _, err := c.Store.Delete(ctx, k, cur.Revision); err != nil && !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
			return false, err
		}
	}
	return false, ErrBusy
}

// holds reports whether h, as the store has it now, still holds value.
func (c *Claims) holds(ctx context.Context, h Holder, value string, uses Uses) (bool, error) {
	o, err := c.Store.Get(ctx, store.Key{Kind: h.Kind, Namespace: h.Namespace, Name: h.Name})
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var m struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(o.Data, &m); err != nil {
		return false, err
	}
	if m.Metadata.UID != h.UID {
		return false, nil // a new object under the old name
	}
	if v, err := strconv.ParseInt(h.Version, 10, 64); err != nil || o.Revision <= v {
		return true, nil // not written since it claimed: its write may still be coming
	}
	return uses(o.Data, value), nil
}

// Drop removes pool/value when uid holds it. A refused update uses it to put back a port it just
// took. A value someone else holds, or that is already gone, is left as it is.
func (c *Claims) Drop(ctx context.Context, pool, value, uid string) error {
	if c == nil || uid == "" {
		return nil
	}
	k := key(pool, value)
	cur, err := c.Store.Get(ctx, k)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var h Holder
	if json.Unmarshal(cur.Data, &h) != nil || h.UID != uid {
		return nil
	}
	if _, err = c.Store.Delete(ctx, k, cur.Revision); errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict) {
		return nil
	}
	return err
}

// Who reads the holder of value in pool.
func (c *Claims) Who(ctx context.Context, pool, value string) (Holder, bool) {
	cur, err := c.Store.Get(ctx, key(pool, value))
	if err != nil {
		return Holder{}, false
	}
	var h Holder
	if json.Unmarshal(cur.Data, &h) != nil || h.UID == "" {
		return Holder{}, false
	}
	return h, true
}

// LetGo removes every claim h holds in pool except those on keep: the values it no longer uses.
func (c *Claims) LetGo(ctx context.Context, pool string, uid string, keep ...string) error {
	objs, _, err := c.Store.List(ctx, store.Selector{Kind: Kind, Namespace: pool})
	if err != nil {
		return err
	}
	kept := map[string]bool{}
	for _, v := range keep {
		kept[v] = true
	}
	var errs []error
	for _, o := range objs {
		var h Holder
		if json.Unmarshal(o.Data, &h) != nil || h.UID != uid || kept[o.Name] {
			continue
		}
		if _, err := c.Store.Delete(ctx, o.Key, o.Revision); err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
