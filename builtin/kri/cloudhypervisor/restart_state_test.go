package cloudhypervisor

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// silo.json is written through Local.WriteFile on every start, volume change and reset. A reader
// (a restarted kevasod, or one killed mid-write) must only ever see the old file or the new one:
// a truncated one reads as no silo, and Create then images a fresh root disk over the old one.
func TestLocalWriteFileIsNeverSeenHalfWritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "silo.json")
	a, b := bytes.Repeat([]byte("a"), 1<<20), bytes.Repeat([]byte("b"), 1<<20)
	if err := (Local{}).WriteFile(p, a, 0o600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			next := b
			if i%2 == 1 {
				next = a
			}
			if err := (Local{}).WriteFile(p, next, 0o600); err != nil {
				t.Error(err)
				return
			}
		}
		close(stop)
	}()
	torn := 0
	for done := false; !done; {
		select {
		case <-stop:
			done = true
		default:
		}
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, a) && !bytes.Equal(got, b) {
			torn++
		}
	}
	wg.Wait()
	if torn > 0 {
		t.Fatalf("a reader saw a half-written file %d times", torn)
	}
	if m, _ := filepath.Glob(p + "*"); len(m) != 1 {
		t.Fatalf("left behind: %v", m)
	}
}
