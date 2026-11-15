package fence

import (
	"context"
	"testing"
	"time"

	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// K-072: the watcher counts the silence on the boot clock the record carries. A wall clock
// stepped back (LastContact says just now) must not keep a silo running past its after.
func TestTheWatcherCountsSilenceOnTheBootClock(t *testing.T) {
	dir := t.TempDir()
	rt := fake.New()
	id := kri.ID{Namespace: "dev", Name: "single", UID: "u1"}
	if err := rt.Create(context.Background(), kri.Spec{ID: id, Image: "x"}); err != nil {
		t.Fatal(err)
	}
	_ = rt.Start(context.Background(), id)
	boot := 10 * time.Hour // the boot clock now
	now := time.Now()
	if err := Write(dir, Record{Version: RecordVersion, LastContact: now, Written: now, BootID: "b1", ContactBoot: boot - 3*time.Minute,
		Silos: []Silo{{ID: id, Runtime: "docker", StopAfter: 2 * time.Minute}}}); err != nil {
		t.Fatal(err)
	}
	w := &Watcher{Dir: dir, Runtimes: map[string]kri.Runtime{"docker": rt}, FenceAfter: DefaultAfter,
		Now: func() time.Time { return now }, Boot: func() (string, time.Duration) { return "b1", boot }, Log: t.Logf}
	w.Check(context.Background())
	if st, _ := rt.Status(context.Background(), id); st.State == kri.Running {
		t.Fatal("3 minutes silent on the boot clock, the wall clock stepped back: the silo with after 2m runs on")
	}
	// Another boot: the readings don't compare; the wall clock is all there is.
	_ = rt.Start(context.Background(), id)
	w = &Watcher{Dir: dir, Runtimes: map[string]kri.Runtime{"docker": rt}, FenceAfter: DefaultAfter,
		Now: func() time.Time { return now }, Boot: func() (string, time.Duration) { return "b2", time.Minute }, Log: t.Logf}
	w.Check(context.Background())
	if st, _ := rt.Status(context.Background(), id); st.State != kri.Running {
		t.Fatal("a boot clock of another boot was compared")
	}
}
