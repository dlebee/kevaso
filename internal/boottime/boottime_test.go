package boottime

import (
	"testing"
	"time"
)

func TestNowGoesOnAndNeverBack(t *testing.T) {
	a := Now()
	time.Sleep(20 * time.Millisecond)
	b := Now()
	if b-a < 20*time.Millisecond {
		t.Fatalf("%s then %s", a, b)
	}
	if Since(a) < b-a {
		t.Fatal("Since is short")
	}
}
