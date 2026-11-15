package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/testports"
)

// A system node whose data is gone (Linode finding: cp1 of a healthy cluster of three, its
// /var/lib/kevaso wiped) refuses to start, and is told the fix that matches what it was, from what
// is left on it: its unit's flags (a store with peers: it may be one of several system nodes) and
// its cluster record. It is never told to make a cluster when it has a record, or when it may be a
// member of one that still runs (kvoadm init there makes a second cluster). And the refusal exits
// with ExitRefused, which the unit doesn't restart on.
func TestAWipedSystemNodeIsToldTheFixThatMatchesWhatItWas(t *testing.T) {
	ha := func(t *testing.T, data string) Config {
		cfg := cpConfig(t, data)
		cfg.Store, cfg.Etcd.PeerListen, cfg.Etcd.ClientListen = StoreEtcd, testports.Reserve(t), "127.0.0.1:0"
		return cfg
	}
	single := cpConfig
	withRecord := func(t *testing.T, data string) {
		if err := writeRecord(data, ClusterRecord{Cluster: "test", ID: "c1", State: RecordInitialized, Created: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	member := []string{"kvoadm host remove cp-1", "kvoadm reset", "kvoadm host add cp-1 --install control-plane", "kvoadm init --restore"}
	for _, tc := range []struct {
		name   string
		cfg    func(*testing.T, string) Config
		record bool
		want   []string
		never  []string
	}{
		{"wiped, set up with peers (one of several system nodes)", ha, false, member, []string{"kvoadm init creates", "then kvoadm init)"}},
		{"store gone, record kept, with peers", ha, true, member, []string{"kvoadm init creates", "then kvoadm init)"}},
		{"wiped, a single system node", single, false, []string{"kvoadm init --restore", "on purpose (kvoadm reset, then kvoadm init)"}, []string{"kvoadm host remove"}},
		{"store gone, record kept, a single system node", single, true, []string{"kvoadm init --restore"}, []string{"then kvoadm init)", "kvoadm init creates", "kvoadm host remove"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := filepath.Join(t.TempDir(), "d")
			if tc.record {
				withRecord(t, data)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := Start(ctx, tc.cfg(t, data))
			var ce *ClusterError
			if !errors.As(err, &ce) {
				t.Fatalf("not a refusal: %v", err)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the refusal doesn't say %q:\n%v", w, err)
				}
			}
			for _, n := range tc.never {
				if strings.Contains(err.Error(), n) {
					t.Errorf("the refusal says %q:\n%v", n, err)
				}
			}
			if ExitCode(err) != ExitRefused || ExitRefused == 1 {
				t.Errorf("exit status %d for a refusal, want %d (not restarted by the unit)", ExitCode(err), ExitRefused)
			}
		})
	}
	if ExitCode(errors.New("a crash")) != 1 {
		t.Fatal("any other failure must exit 1: the unit restarts it")
	}
}
