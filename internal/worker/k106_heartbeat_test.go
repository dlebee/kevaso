package worker

import (
	"context"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/store"
)

// K-106, the worker's half: what a heartbeat sends never equals the stamp it read, so a server
// that stores it as sent (one without authentication, which knows no host to stamp for) still
// stores a new stamp on every beat, and the control plane counts every one as a contact. Two
// beats within one second used to send the same second twice.
func TestK106AHeartbeatNeverSendsTheStampItRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clk := clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC))
	srv, err := apiserver.New(store.NewMemory(0), clk)
	if err != nil {
		t.Fatal(err)
	}
	c, closeC := srv.InProcess()
	defer closeC()
	if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "w1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	contacts := hostctl.NewContacts(clk.Now())
	for beat := 0; beat < 4; beat++ {
		beatOnce(ctx, t, c, clk)
		var got v1.Host
		if err := c.Get(ctx, "Host", "", "w1", &got); err != nil {
			t.Fatal(err)
		}
		contacts.Observe(&got, clk.Now())
		if s := contacts.Silence("w1", clk.Now()); s != 0 {
			t.Fatalf("beat %d (stored %v): the write got through, and the control plane counts %v of silence", beat, got.Status.LastHeartbeat, s)
		}
		clk.Step(300 * time.Millisecond)
	}
}

// beatOnce sends one heartbeat: Heartbeat reports at once, then waits for a tick an hour away.
func beatOnce(ctx context.Context, t *testing.T, c *client.Client, clk clock.Clock) {
	t.Helper()
	var contact Contact
	bctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Heartbeat(bctx, c, "w1", time.Hour, clk, t.Logf, &contact)
	}()
	for contact.Last().IsZero() {
		if ctx.Err() != nil {
			t.Fatal("the heartbeat never got through")
		}
		time.Sleep(time.Millisecond)
	}
	stop()
	<-done
}
