//go:build !unix

package kvo

// onResize: no SIGWINCH here; the terminal keeps the size it started with.
func onResize(func()) (stop func()) { return func() {} }
