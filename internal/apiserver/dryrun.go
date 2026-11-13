package apiserver

import (
	"context"
	"net/http"

	"kevaso.com/core/internal/store"
)

// Dry runs: a write with ?dryRun=All goes through everything a write does — decoding, defaults,
// mutation policies, guards, rules, validation policies, the resourceVersion check — and answers
// with the object it would store, but stores nothing (kvo apply uses it to tell "unchanged").

type dryRunKey struct{}

func withDryRun(ctx context.Context, r *http.Request) context.Context {
	if r.URL.Query().Get("dryRun") == "All" {
		return context.WithValue(ctx, dryRunKey{}, true)
	}
	return ctx
}

func dryRun(ctx context.Context) bool {
	v, _ := ctx.Value(dryRunKey{}).(bool)
	return v
}

func (s *Server) commitCreate(ctx context.Context, k store.Key, data []byte) (store.Object, error) {
	if !dryRun(ctx) {
		return s.store.Create(ctx, k, data)
	}
	if _, err := s.store.Get(ctx, k); err == nil {
		return store.Object{}, store.ErrExists
	}
	return store.Object{Key: k, Data: data}, nil
}

func (s *Server) commitUpdate(ctx context.Context, k store.Key, data []byte, expected int64) (store.Object, error) {
	if !dryRun(ctx) {
		return s.store.Update(ctx, k, data, expected)
	}
	cur, err := s.store.Get(ctx, k)
	if err != nil {
		return store.Object{}, err
	}
	if cur.Revision != expected {
		return store.Object{}, store.ErrConflict
	}
	return store.Object{Key: k, Data: data, Revision: cur.Revision}, nil
}

func (s *Server) commitDelete(ctx context.Context, k store.Key, expected int64) (store.Object, error) {
	if !dryRun(ctx) {
		return s.store.Delete(ctx, k, expected)
	}
	cur, err := s.store.Get(ctx, k)
	if err != nil {
		return store.Object{}, err
	}
	if cur.Revision != expected {
		return store.Object{}, store.ErrConflict
	}
	return store.Object{Key: k}, nil
}
