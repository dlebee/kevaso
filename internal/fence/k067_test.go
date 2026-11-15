package fence

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// K-067: "armed" must mean a watcher is running that reads this record version. The watcher
// stamps, on every check, its record version and the boot clock; the agent arms only on a fresh
// stamp of its own boot.
func TestTheWatcherStampsItsVersionAndLiveness(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, Record{Version: RecordVersion}); err != nil {
		t.Fatal(err)
	}
	boot := 5 * time.Hour
	w := &Watcher{Dir: dir, Runtimes: map[string]kri.Runtime{}, FenceAfter: DefaultAfter, Boot: func() (string, time.Duration) { return "b1", boot }, Log: t.Logf}
	w.Check(context.Background())
	s, ok, err := ReadStamp(dir)
	if err != nil || !ok || s.Version != RecordVersion || s.BootID != "b1" || s.Boot != boot {
		t.Fatalf("stamp %+v %v %v", s, ok, err)
	}
	if !Live(s, "b1", boot+2*time.Second) {
		t.Error("a stamp 2s old isn't live")
	}
	if Live(s, "b1", boot+StampFresh+time.Second) {
		t.Error("a stale stamp is live: the watcher may have died")
	}
	if Live(s, "b2", boot) {
		t.Error("a stamp of another boot is live")
	}
	if old := (Stamp{Version: RecordVersion - 1, BootID: "b1", Boot: boot}); Live(old, "b1", boot) {
		t.Error("a watcher of an older record version is live: it would read the record its old way")
	}
}

// liar reports a kill done while the silo still runs.
type liar struct {
	*fake.Runtime
	kills atomic.Int32
}

func (l *liar) Kill(context.Context, kri.ID) error { l.kills.Add(1); return nil }

// K-067: a kill is done only once the silo is confirmed not running; a silo whose runtime this
// watcher doesn't have is never counted done (tried on every check, and reported).
func TestAKillIsDoneOnlyOnceConfirmed(t *testing.T) {
	dir := t.TempDir()
	rt := &liar{Runtime: fake.New()}
	id := kri.ID{Namespace: "dev", Name: "single", UID: "u1"}
	gone := kri.ID{Namespace: "dev", Name: "other", UID: "u2"}
	_ = rt.Create(context.Background(), kri.Spec{ID: id, Image: "x"})
	_ = rt.Start(context.Background(), id)
	now := time.Now()
	if err := Write(dir, Record{Version: RecordVersion, LastContact: now.Add(-time.Hour), Written: now, Silos: []Silo{
		{ID: id, Runtime: "docker", StopAfter: time.Minute}, {ID: gone, Runtime: "podman", StopAfter: time.Minute}}}); err != nil {
		t.Fatal(err)
	}
	w := &Watcher{Dir: dir, Runtimes: map[string]kri.Runtime{"docker": rt}, FenceAfter: DefaultAfter, Now: func() time.Time { return now }, Log: t.Logf}
	w.Check(context.Background())
	w.Check(context.Background())
	if n := rt.kills.Load(); n != 2 {
		t.Errorf("killed %d times: a kill that left it running counted as done", n)
	}
	if w.done[id.UID] || w.done[gone.UID] {
		t.Errorf("done: %v", w.done)
	}
}
