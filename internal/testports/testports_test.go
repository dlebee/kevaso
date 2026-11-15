//go:build unix

package testports

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

// Ports handed out are distinct while held, outside the OS's ephemeral range, and free to bind.
func TestReservedPortsAreDistinctAndBindable(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		a := Reserve(t)
		if seen[a] {
			t.Fatalf("%s handed out twice while held", a)
		}
		seen[a] = true
		p, _ := strconv.Atoi(a[strings.LastIndex(a, ":")+1:])
		if p < first || p >= first+count {
			t.Fatalf("%s outside the range", a)
		}
	}
	for a := range seen {
		l, err := net.Listen("tcp", a)
		if err != nil {
			t.Fatalf("a reserved port can't be bound: %v", err)
		}
		_ = l.Close()
	}
}

// Held means held: while one test holds a port, Reserve never gives it out again, here or in
// another process (the lock is on a shared file).
func TestAHeldPortIsNotHandedOutAgain(t *testing.T) {
	a := Reserve(t)
	for range 3000 {
		if b := Reserve(t); b == a {
			t.Fatalf("%s handed out while held", a)
		}
	}
}
