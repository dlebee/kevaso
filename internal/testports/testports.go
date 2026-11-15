//go:build unix

// Package testports hands tests TCP ports they must name before anything binds them (an etcd
// member's peer URL is announced before the member starts). A port taken by binding port 0 and
// closed again is the OS's to hand out next: to any other test's port-0 listener and to any
// outgoing connection's local end. On a busy runner that happens between the close and the bind
// ("address already in use"). So these ports come from a range no OS hands out by itself, and
// each is held for the test's lifetime by an exclusive lock on a file shared by every test
// process of this user (flock: released when the test ends, or when its process dies).
package testports

import (
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// The range: below every OS's ephemeral ports (Linux 32768–60999, macOS and Windows 49152–65535,
// FreeBSD 10000–65535 when changed: it isn't by default) and above the well-known ones.
const (
	first = 20000
	count = 10000
)

// Reserve returns 127.0.0.1:PORT, free now and reserved for no other test until t ends.
func Reserve(t testing.TB) string {
	t.Helper()
	dir := filepath.Join(os.TempDir(), "kevaso-test-ports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for range 2000 {
		port := first + rand.IntN(count)
		f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(port)), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
			_ = f.Close() // another test holds it
			continue
		}
		addr := "127.0.0.1:" + strconv.Itoa(port)
		l, err := net.Listen("tcp", addr)
		if err != nil { // something outside the tests uses it
			_ = f.Close()
			continue
		}
		_ = l.Close()
		t.Cleanup(func() { _ = f.Close() }) // closing releases the lock
		return addr
	}
	t.Fatal("no free test port in 127.0.0.1:20000-29999")
	return ""
}
