package apiserver

import (
	"context"
	"net/http"
	"strings"
	"sync"
)

// Warnings: what admission accepts but the user should know (kvo prints them), sent as HTTP
// Warning headers (RFC 9111 §5.5: code 299, agent "-", a quoted text) on a create or update that
// succeeded.

type warningsKey struct{}

type warnings struct {
	mu   sync.Mutex
	list []string
}

// withWarnings collects the warnings of one request.
func withWarnings(ctx context.Context) (context.Context, *warnings) {
	w := &warnings{}
	return context.WithValue(ctx, warningsKey{}, w), w
}

// warn adds a warning to the request's answer (none if the request collects none).
func warn(ctx context.Context, text string) {
	w, _ := ctx.Value(warningsKey{}).(*warnings)
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, t := range w.list {
		if t == text {
			return
		}
	}
	w.list = append(w.list, text)
}

// set puts the warnings in h.
func (w *warnings) set(h http.Header) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, t := range w.list {
		t = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ", "\r", " ").Replace(t)
		h.Add("Warning", `299 - "`+t+`"`)
	}
}
