//go:build unix

package kvo

import (
	"os"
	"os/signal"
	"syscall"
)

// onResize calls f each time this terminal changes size, until the returned stop is called.
func onResize(f func()) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				f()
			case <-done:
				return
			}
		}
	}()
	return func() { signal.Stop(ch); close(done) }
}
