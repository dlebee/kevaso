// Package informer keeps a local, watch-fed cache of one kind, the way client-go's informers do:
// list once, then watch from the list's revision; when the watch ends (server restart, compaction,
// network), list again and tell handlers about everything that changed meanwhile. Controllers read
// from the cache and get told which keys to look at — never what changed.
package informer

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Key names a cached object.
type Key struct{ Namespace, Name string }

// Informer caches every object of one kind (all namespaces).
type Informer struct {
	c    *client.Client
	kind string

	mu       sync.RWMutex
	items    map[Key]meta.Object
	handlers []func(Key)
	synced   chan struct{}
	once     sync.Once
}

// New returns an informer for kind. Call Run to start it.
func New(c *client.Client, kind string) *Informer {
	return &Informer{c: c, kind: kind, items: map[Key]meta.Object{}, synced: make(chan struct{})}
}

// Kind is the kind this informer caches.
func (i *Informer) Kind() string { return i.kind }

// AddHandler is called with the key of every object that is added, changed or removed. Register
// handlers before Run. Handlers must not block.
func (i *Informer) AddHandler(h func(Key)) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.handlers = append(i.handlers, h)
}

// WaitSynced blocks until the first list has been loaded (or ctx ends).
func (i *Informer) WaitSynced(ctx context.Context) bool {
	select {
	case <-i.synced:
		return true
	case <-ctx.Done():
		return false
	}
}

// Get returns a copy of a cached object.
func (i *Informer) Get(namespace, name string) (meta.Object, bool) {
	i.mu.RLock()
	o, ok := i.items[Key{namespace, name}]
	i.mu.RUnlock()
	if !ok {
		return nil, false
	}
	c, err := v1.Clone(o)
	return c, err == nil
}

// List returns copies of every cached object, sorted by namespace and name.
func (i *Informer) List() []meta.Object {
	i.mu.RLock()
	keys := make([]Key, 0, len(i.items))
	for k := range i.items {
		keys = append(keys, k)
	}
	i.mu.RUnlock()
	sort.Slice(keys, func(a, b int) bool {
		if keys[a].Namespace != keys[b].Namespace {
			return keys[a].Namespace < keys[b].Namespace
		}
		return keys[a].Name < keys[b].Name
	})
	out := make([]meta.Object, 0, len(keys))
	for _, k := range keys {
		if o, ok := i.Get(k.Namespace, k.Name); ok {
			out = append(out, o)
		}
	}
	return out
}

func (i *Informer) notify(keys []Key) {
	i.mu.RLock()
	hs := slices.Clone(i.handlers)
	i.mu.RUnlock()
	for _, k := range keys {
		for _, h := range hs {
			h(k)
		}
	}
}

// Run keeps the cache in sync until ctx ends.
func (i *Informer) Run(ctx context.Context) {
	delay := 100 * time.Millisecond
	for ctx.Err() == nil {
		rv, err := i.relist(ctx)
		if err == nil {
			delay = 100 * time.Millisecond
			err = i.watch(ctx, rv)
		}
		if ctx.Err() != nil {
			return
		}
		select { // back off a little before listing again
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if err != nil && delay < 5*time.Second {
			delay *= 2
		}
	}
}

// relist replaces the cache with a fresh list and reports every key that changed.
func (i *Informer) relist(ctx context.Context) (string, error) {
	l, err := i.c.List(ctx, i.kind, "")
	if err != nil {
		return "", err
	}
	fresh := map[Key]meta.Object{}
	for _, raw := range l.Items {
		o, _, err := v1.Decode(raw)
		if err != nil {
			return "", err
		}
		m := o.GetObjectMeta()
		fresh[Key{m.Namespace, m.Name}] = o
	}
	i.mu.Lock()
	var changed []Key
	for k, o := range fresh {
		if old, ok := i.items[k]; !ok || old.GetObjectMeta().ResourceVersion != o.GetObjectMeta().ResourceVersion {
			changed = append(changed, k)
		}
	}
	for k := range i.items {
		if _, ok := fresh[k]; !ok {
			changed = append(changed, k)
		}
	}
	i.items = fresh
	i.mu.Unlock()
	i.once.Do(func() { close(i.synced) })
	i.notify(changed)
	return l.Metadata.ResourceVersion, nil
}

func (i *Informer) watch(ctx context.Context, rv string) error {
	ch, err := i.c.Watch(ctx, i.kind, "", rv)
	if err != nil {
		return err
	}
	for ev := range ch {
		o, _, err := v1.Decode(ev.Object)
		if err != nil {
			return err
		}
		m := o.GetObjectMeta()
		k := Key{m.Namespace, m.Name}
		i.mu.Lock()
		if ev.Type == "DELETED" {
			delete(i.items, k)
		} else {
			i.items[k] = o
		}
		i.mu.Unlock()
		i.notify([]Key{k})
	}
	return nil // the server ended the stream: relist
}
