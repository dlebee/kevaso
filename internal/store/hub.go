package store

import (
	"context"
	"errors"
	"sync"
)

// ErrClosed: the store was closed.
var ErrClosed = errors.New("store closed")

// watchBuffer is how many events a watcher may lag behind before it's dropped (and must re-list).
const watchBuffer = 1024

// hub fans events out to watchers. Its methods are called with the owning store's write lock held,
// which is what keeps the backlog/live hand-over gap-free; it has its own lock for unsubscribing.
type hub struct {
	mu   sync.Mutex
	subs map[*watcher]struct{}
}

type watcher struct {
	sel  Selector
	ch   chan Event
	once sync.Once
}

func (w *watcher) close() { w.once.Do(func() { close(w.ch) }) }

// subscribe returns a channel that first delivers backlog, then live events, until ctx ends.
func (h *hub) subscribe(ctx context.Context, sel Selector, backlog []Event) <-chan Event {
	size := watchBuffer
	if len(backlog) > size {
		size = len(backlog) + watchBuffer
	}
	w := &watcher{sel: sel, ch: make(chan Event, size)}
	for _, ev := range backlog {
		w.ch <- cloneEvent(ev)
	}
	h.mu.Lock()
	if h.subs == nil {
		h.subs = map[*watcher]struct{}{}
	}
	h.subs[w] = struct{}{}
	h.mu.Unlock()
	go func() {
		<-ctx.Done()
		h.drop(w)
	}()
	return w.ch
}

// publish delivers an event to every matching watcher; one that can't keep up is dropped.
func (h *hub) publish(ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for w := range h.subs {
		if !w.sel.Matches(ev.Object.Key) {
			continue
		}
		select {
		case w.ch <- cloneEvent(ev):
		default:
			delete(h.subs, w)
			w.close()
		}
	}
}

func (h *hub) drop(w *watcher) {
	h.mu.Lock()
	delete(h.subs, w)
	h.mu.Unlock()
	w.close()
}

func (h *hub) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for w := range h.subs {
		w.close()
	}
	h.subs = nil
}

func cloneEvent(ev Event) Event { ev.Object = clone(ev.Object); return ev }
