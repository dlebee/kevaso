package plugins

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// serveFake serves a fake plugin at sock until the returned stop is called (which, as a plugin's
// restart does, removes the socket).
func serveFake(t *testing.T, sock string, f *kplugintest.Fake) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = kplugin.Serve(ctx, sock, f) }()
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var once atomic.Bool
	stop = func() {
		if once.CompareAndSwap(false, true) {
			cancel()
			<-done
		}
	}
	t.Cleanup(stop)
	return stop
}

// K-040: one missed Info (a plugin restarting, being upgraded) dropped the plugin and everything
// it serves at once; the scheduler then wrote its load-balancer addresses and node ports away. Now
// a plugin that stops answering, or whose socket is gone, keeps its last answer for Hold (ten
// minutes by default), says so in the log and in every error a call to it returns, and is dropped
// only when it hasn't answered for that long.
func TestAPluginThatMissesInfoIsKeptForTheHold(t *testing.T) {
	if DefaultHold != 10*time.Minute {
		t.Fatalf("the hold is %s, want ten minutes", DefaultHold)
	}
	dir, _ := os.MkdirTemp("", "kph")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "fake", "plugin.sock")
	var changes atomic.Int32
	var l logs
	r := &Registry{Dir: dir, Hold: 3 * time.Second, Log: l.logf, OnChange: func() { changes.Add(1) }}
	ctx := context.Background()

	stop := serveFake(t, sock, kplugintest.New())
	r.scan(ctx, dir)
	if _, _, ok := r.Storage(kplugintest.ClassBlock); !ok || changes.Load() != 1 {
		t.Fatalf("never registered (changes %d): %s", changes.Load(), l.all())
	}

	// The plugin restarts: its socket goes away for a moment. It is kept, marked away.
	stop()
	r.scan(ctx, dir)
	p, _, ok := r.Storage(kplugintest.ClassBlock)
	if !ok {
		t.Fatalf("one missed Info dropped the plugin: %s", l.all())
	}
	if since, why := p.Away(); since.IsZero() || why == "" {
		t.Fatalf("not marked away: %v %q", since, why)
	}
	if changes.Load() != 1 {
		t.Fatalf("a missed Info changed what is served (%d changes)", changes.Load())
	}
	if got := l.all(); !strings.Contains(got, "plugin fake") || !strings.Contains(got, "kept until") {
		t.Fatalf("the log doesn't say it is kept:\n%s", got)
	}
	// A call to it fails (nothing answers) and says how long it is kept.
	_, err := p.Conn.EnsureVolume(ctx, kplugin.Volume{Class: kplugintest.ClassBlock, ID: "u/v"})
	if err == nil || !strings.Contains(err.Error(), "has not answered since") || !strings.Contains(err.Error(), "kept until") {
		t.Fatalf("a call to an away plugin: %v", err)
	}

	// It comes back within the hold: answering again, nothing dropped, nothing changed.
	stop = serveFake(t, sock, kplugintest.New())
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		r.scan(ctx, dir) // gRPC reconnects on its own backoff
		if p, _, _ := r.Storage(kplugintest.ClassBlock); p != nil {
			if since, _ := p.Away(); since.IsZero() {
				break
			}
		}
	}
	p, _, ok = r.Storage(kplugintest.ClassBlock)
	if since, _ := p.Away(); !ok || !since.IsZero() || changes.Load() != 1 {
		t.Fatalf("back: ok %v, away since %v, changes %d", ok, since, changes.Load())
	}
	if !strings.Contains(l.all(), "answering again") {
		t.Fatalf("the log doesn't say it's back:\n%s", l.all())
	}

	// Gone for good: kept until the hold has passed, then dropped.
	stop()
	r.scan(ctx, dir)
	if _, _, ok := r.Storage(kplugintest.ClassBlock); !ok {
		t.Fatal("dropped before the hold")
	}
	time.Sleep(3100 * time.Millisecond)
	r.scan(ctx, dir)
	if _, _, ok := r.Storage(kplugintest.ClassBlock); ok || changes.Load() != 2 {
		t.Fatalf("still served after the hold (changes %d):\n%s", changes.Load(), l.all())
	}
	if !strings.Contains(l.all(), "plugin fake gone") {
		t.Fatalf("the drop isn't logged:\n%s", l.all())
	}
}

// failingInfo is a plugin whose socket is there but whose Info fails (a plugin stuck starting up).
type failingInfo struct {
	*kplugintest.Fake
	fail atomic.Bool
}

func (f *failingInfo) Info(ctx context.Context) (kplugin.Info, error) {
	if f.fail.Load() {
		return kplugin.Info{}, errors.New("starting up")
	}
	return f.Fake.Info(ctx)
}

// The same when the socket is there and Info fails.
func TestAPluginWhoseInfoFailsIsKeptForTheHold(t *testing.T) {
	dir, _ := os.MkdirTemp("", "kph")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "fake", "plugin.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &failingInfo{Fake: kplugintest.New()}
	go func() { _ = kplugin.Serve(ctx, sock, f) }()
	var l logs
	r := &Registry{Dir: dir, Hold: 300 * time.Millisecond, Log: l.logf}
	for i := 0; i < 100; i++ {
		if r.scan(ctx, dir); len(r.All()) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(r.All()) != 1 {
		t.Fatalf("never registered: %s", l.all())
	}
	f.fail.Store(true)
	r.scan(ctx, dir)
	if _, _, ok := r.Storage(kplugintest.ClassBlock); !ok {
		t.Fatalf("one failed Info dropped it: %s", l.all())
	}
	if !strings.Contains(l.all(), "starting up") {
		t.Fatalf("the log doesn't say why:\n%s", l.all())
	}
	time.Sleep(400 * time.Millisecond)
	r.scan(ctx, dir)
	if len(r.All()) != 0 {
		t.Fatalf("still served after the hold: %s", l.all())
	}
}
