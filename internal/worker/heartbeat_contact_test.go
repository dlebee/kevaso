package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/boottime"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// §0.7's margin (silo.StopMargin) rests on both sides counting from one heartbeat: the agent from
// when it SENT its last heartbeat that got through, the control plane from when it saw it, never
// earlier. A contact marked when the answer arrived (a slow answer) would let the agent's fence
// end later than the control plane's count, and two copies run.
func TestContactIsWhenTheHeartbeatWasSent(t *testing.T) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			time.Sleep(time.Second) // the status write answers late
		}
		srv.ServeHTTP(w, r)
	})
	ts := httptest.NewServer(slow)
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "w1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	contact := &Contact{}
	before := time.Now()
	go Heartbeat(ctx, c, "w1", time.Hour, clock.Real{}, t.Logf, contact)
	for deadline := time.Now().Add(10 * time.Second); contact.Last().IsZero(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no contact marked")
		}
	}
	if late := contact.Last().Sub(before); late > 500*time.Millisecond {
		t.Fatalf("contact marked %s after the heartbeat began: when the answer came, not when it was sent", late)
	}
}

// K-072: the contact is also timed on the boot clock, which no time server steps.
func TestContactKeepsTheBootClockReading(t *testing.T) {
	c := &Contact{}
	before := boottime.Now()
	c.Mark(time.Now().Add(-time.Hour), boottime.Now()) // a wall clock stepped back an hour
	got, ok := c.LastBoot()
	if !ok || got < before || boottime.Since(got) > time.Second {
		t.Fatalf("boot reading %s (ok %v), want just now", got, ok)
	}
}
