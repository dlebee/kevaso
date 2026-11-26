package integration

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

// timedStore runs a hook once, at a chosen point of one store call, to put a second request in
// the window between two steps of another.
type timedStore struct {
	store.Store
	mu         sync.Mutex
	afterList  func(store.Selector) bool // true: run then disarm
	beforeMake func(store.Key) bool
}

func (s *timedStore) List(ctx context.Context, sel store.Selector) ([]store.Object, int64, error) {
	objs, rev, err := s.Store.List(ctx, sel)
	s.mu.Lock()
	f := s.afterList
	s.mu.Unlock()
	if f != nil && f(sel) {
		s.mu.Lock()
		s.afterList = nil
		s.mu.Unlock()
	}
	return objs, rev, err
}

func (s *timedStore) Create(ctx context.Context, k store.Key, data []byte) (store.Object, error) {
	s.mu.Lock()
	f := s.beforeMake
	s.mu.Unlock()
	if f != nil && f(k) {
		s.mu.Lock()
		s.beforeMake = nil
		s.mu.Unlock()
	}
	return s.Store.Create(ctx, k, data)
}

// Rule 3 across a namespace's delete: a secret written while the namespace is being deleted
// (after the delete found it empty, or after the write found the namespace there) is never left
// under the name for whoever is given a namespace of that name next.
func TestASecretWrittenDuringANamespaceDeleteNeverReachesTheNextOwner(t *testing.T) {
	for _, window := range []string{"after the emptiness check", "after the write's namespace check"} {
		t.Run(window, func(t *testing.T) {
			ts := &timedStore{Store: store.NewMemory(0)}
			c := newClusterOn(t, ts)
			if err := c.admin.Create(c.ctx, ns("web3")); err != nil {
				t.Fatal(err)
			}
			// The old owner's write (through the admin socket: a binding of theirs in web3 would
			// itself keep the namespace from being deleted).
			ada := c.admin

			var created, deleted error
			isSecret := func(namespace, kind string) bool { return kind == "Secret" && namespace == "web3" }
			if window == "after the emptiness check" {
				ts.mu.Lock()
				ts.afterList = func(sel store.Selector) bool {
					if !isSecret(sel.Namespace, sel.Kind) {
						return false
					}
					created = ada.Create(c.ctx, secretObj("db-root", nil, "ada-root-password"))
					return true
				}
				ts.mu.Unlock()
				deleted = c.admin.Delete(c.ctx, "Namespace", "", "web3")
			} else {
				ts.mu.Lock()
				ts.beforeMake = func(k store.Key) bool {
					if !isSecret(k.Namespace, k.Kind) {
						return false
					}
					deleted = c.admin.Delete(c.ctx, "Namespace", "", "web3")
					return true
				}
				ts.mu.Unlock()
				created = ada.Create(c.ctx, secretObj("db-root", nil, "ada-root-password"))
			}
			t.Logf("create: %v; namespace delete: %v", created, deleted)
			if created == nil && deleted == nil {
				t.Errorf("both the secret's create and the namespace's delete succeeded")
			}
			if deleted != nil {
				return // the namespace (and the secret, if it was made) is still ada's
			}

			// The name is free: a namespace of that name goes to someone else.
			if err := c.admin.Create(c.ctx, ns("web3")); err != nil {
				t.Fatal(err)
			}
			if err := c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
				ObjectMeta: meta.ObjectMeta{Name: "bob", Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "admin"},
				Subjects: []v1.Subject{{Kind: "User", Name: "bob"}}}); err != nil {
				t.Fatal(err)
			}
			bob := c.as(t, "bob")
			if err := bob.Get(c.ctx, "Secret", "web3", "db-root", &v1.Secret{}); !client.IsNotFound(err) {
				t.Errorf("the next owner of web3 gets the old owner's secret: %v, want 404", err)
			}
			var v client.SecretValue
			if err := bob.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/db-root/value?key=token", nil, &v); err == nil || string(v.Value) != "" {
				t.Errorf("the next owner of web3 reads the old owner's secret value %q (%v)", v.Value, err)
			}
		})
	}
}
