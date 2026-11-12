package rbac

import (
	"context"
	"sync"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

// Kinds RBAC reads.
var Kinds = []string{"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}

// Source serves the current Policy from a store, rebuilt only when the store has changed since.
type Source struct {
	Store store.Store

	mu  sync.Mutex
	rev int64
	p   *Policy
}

// Policy returns a snapshot no older than the store's current revision.
func (s *Source) Policy(ctx context.Context) (*Policy, error) {
	rev, err := s.Store.Revision(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.p != nil && s.rev == rev {
		return s.p, nil
	}
	var objs []meta.Object
	var seen int64
	for _, k := range Kinds {
		list, r, err := s.Store.List(ctx, store.Selector{Kind: k})
		if err != nil {
			return nil, err
		}
		seen = max(seen, r)
		for _, o := range list {
			obj, _, err := v1.Decode(o.Data)
			if err != nil {
				return nil, err
			}
			objs = append(objs, obj)
		}
	}
	s.p, s.rev = NewPolicy(objs), min(rev, seen)
	return s.p, nil
}
