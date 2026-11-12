package store

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
)

// Memory is an in-memory Store: for unit tests and for running controllers offline.
type Memory struct {
	mu        sync.Mutex
	objects   map[Key]Object
	rev       int64
	history   []Event // events after compactedAt, in revision order
	compacted int64   // events with revision <= compacted are gone
	keep      int     // how many events of history to keep
	hub       hub
	closed    bool
}

// NewMemory returns an empty store keeping the last `keep` events for watches (default 10000).
func NewMemory(keep int) *Memory {
	if keep <= 0 {
		keep = 10000
	}
	return &Memory{objects: map[Key]Object{}, keep: keep}
}

func (m *Memory) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.closed {
		return ErrClosed
	}
	return nil
}

// Get implements Store.
func (m *Memory) Get(ctx context.Context, key Key) (Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return Object{}, err
	}
	o, ok := m.objects[key]
	if !ok {
		return Object{}, fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	return clone(o), nil
}

// List implements Store.
func (m *Memory) List(ctx context.Context, sel Selector) ([]Object, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return nil, 0, err
	}
	var out []Object
	for k, o := range m.objects {
		if sel.Matches(k) {
			out = append(out, clone(o))
		}
	}
	sortObjects(out)
	return out, m.rev, nil
}

// Create implements Store.
func (m *Memory) Create(ctx context.Context, key Key, data []byte) (Object, error) {
	if err := key.Validate(); err != nil {
		return Object{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return Object{}, err
	}
	if _, ok := m.objects[key]; ok {
		return Object{}, fmt.Errorf("%s: %w", key, ErrExists)
	}
	return m.write(Added, key, data), nil
}

// Update implements Store.
func (m *Memory) Update(ctx context.Context, key Key, data []byte, expected int64) (Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return Object{}, err
	}
	cur, ok := m.objects[key]
	if !ok {
		return Object{}, fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	if cur.Revision != expected {
		return Object{}, fmt.Errorf("%s at %d, expected %d: %w", key, cur.Revision, expected, ErrConflict)
	}
	return m.write(Modified, key, data), nil
}

// Delete implements Store.
func (m *Memory) Delete(ctx context.Context, key Key, expected int64) (Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return Object{}, err
	}
	cur, ok := m.objects[key]
	if !ok {
		return Object{}, fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	if expected != 0 && cur.Revision != expected {
		return Object{}, fmt.Errorf("%s at %d, expected %d: %w", key, cur.Revision, expected, ErrConflict)
	}
	return m.write(Deleted, key, cur.Data), nil
}

// write applies one change under m.mu: bump the revision, record the event, notify watchers.
func (m *Memory) write(t EventType, key Key, data []byte) Object {
	m.rev++
	o := Object{Key: key, Revision: m.rev, Data: bytes.Clone(data)}
	if t == Deleted {
		delete(m.objects, key)
	} else {
		m.objects[key] = o
	}
	ev := Event{Type: t, Object: o}
	m.history = append(m.history, ev)
	if over := len(m.history) - m.keep; over > 0 {
		m.compacted = m.history[over-1].Object.Revision
		m.history = append([]Event(nil), m.history[over:]...)
	}
	m.hub.publish(ev)
	return clone(o)
}

// Watch implements Store.
func (m *Memory) Watch(ctx context.Context, sel Selector, from int64) (<-chan Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return nil, err
	}
	if from < m.compacted {
		return nil, fmt.Errorf("watch from %d, history starts after %d: %w", from, m.compacted, ErrCompacted)
	}
	var backlog []Event
	for _, ev := range m.history {
		if ev.Object.Revision > from && sel.Matches(ev.Object.Key) {
			backlog = append(backlog, ev)
		}
	}
	// Subscribing under m.mu means no write can slip between the backlog and the live stream.
	return m.hub.subscribe(ctx, sel, backlog), nil
}

// Revision implements Store.
func (m *Memory) Revision(ctx context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return 0, err
	}
	return m.rev, nil
}

// Close implements Store.
func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.hub.closeAll()
	return nil
}

func clone(o Object) Object { o.Data = bytes.Clone(o.Data); return o }

func sortObjects(os []Object) {
	sort.Slice(os, func(i, j int) bool {
		a, b := os[i].Key, os[j].Key
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
}

var _ Store = (*Memory)(nil)
