// Package store is the control plane's storage: objects keyed by kind/namespace/name, a global
// revision counter, optimistic concurrency, and resumable watches.
//
// Like Kubernetes' etcd layer, every write bumps one cluster-wide revision; an object's resource
// version is the revision of its last write, and a watch resumes from any revision still in the event
// history. The store keeps objects as opaque bytes: types, defaults and validation live above it.
//
// Implementations: Memory (tests, `kvo` offline), SQLite (a single control plane), and later embedded
// etcd (HA, research E021). All of them pass the same conformance suite (storetest).
package store

import (
	"context"
	"errors"
	"fmt"
)

// Key identifies an object. Cluster-scoped kinds use an empty Namespace.
type Key struct {
	Kind      string
	Namespace string
	Name      string
}

func (k Key) String() string {
	if k.Namespace == "" {
		return k.Kind + "/" + k.Name
	}
	return k.Kind + "/" + k.Namespace + "/" + k.Name
}

// Validate reports whether the key is usable.
func (k Key) Validate() error {
	if k.Kind == "" || k.Name == "" {
		return fmt.Errorf("key %q: kind and name are required", k)
	}
	return nil
}

// Object is a stored object: its key, the revision of its last write, and its bytes.
type Object struct {
	Key
	Revision int64
	Data     []byte
}

// EventType says what happened to an object.
type EventType string

const (
	Added    EventType = "ADDED"
	Modified EventType = "MODIFIED"
	Deleted  EventType = "DELETED"
)

// Event is one write. For Deleted, Object holds the last state with the deletion's revision.
type Event struct {
	Type   EventType
	Object Object
}

// Selector picks the objects a List or Watch covers: one kind, optionally one namespace.
type Selector struct {
	Kind      string
	Namespace string // empty: every namespace
}

// Matches reports whether a key is covered.
func (s Selector) Matches(k Key) bool {
	return k.Kind == s.Kind && (s.Namespace == "" || k.Namespace == s.Namespace)
}

var (
	// ErrNotFound: no object with that key.
	ErrNotFound = errors.New("not found")
	// ErrExists: Create on a key that already exists.
	ErrExists = errors.New("already exists")
	// ErrConflict: the expected revision isn't the object's current one (someone wrote first).
	ErrConflict = errors.New("conflict: the object was modified")
	// ErrCompacted: a watch asked to resume from a revision older than the kept history; re-list.
	ErrCompacted = errors.New("revision compacted: re-list and watch again")
)

// Store is what the API server stores objects in.
type Store interface {
	// Get returns the current object.
	Get(ctx context.Context, key Key) (Object, error)
	// List returns every object the selector covers, sorted by key, and the store's revision at
	// that moment: watching from that revision misses nothing.
	List(ctx context.Context, sel Selector) ([]Object, int64, error)
	// Create stores a new object.
	Create(ctx context.Context, key Key, data []byte) (Object, error)
	// Update replaces an object if its current revision is expected (optimistic concurrency).
	Update(ctx context.Context, key Key, data []byte, expected int64) (Object, error)
	// Delete removes an object if its current revision is expected; expected 0 deletes regardless.
	Delete(ctx context.Context, key Key, expected int64) (Object, error)
	// Watch streams every event the selector covers with a revision after from, in order: first the
	// history, then live events. The channel closes when ctx ends, or when the watcher falls too far
	// behind (the client then re-lists). ErrCompacted if from is older than the kept history.
	Watch(ctx context.Context, sel Selector, from int64) (<-chan Event, error)
	// Revision is the store's current revision (the last write's).
	Revision(ctx context.Context) (int64, error)
	// Close releases resources; open watches end.
	Close() error
}
