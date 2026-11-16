package controlplane

import (
	"context"
	"errors"
	"os"
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

// A system node added with kvoadm host add keeps --join in its unit after the one-time token is
// spent. Wiping /var/lib/kevaso leaves no store and no token: kevasod must refuse (ExitRefused,
// which the unit does not restart) and say to remove it and add it again. The Linode run exited 1
// with "joining needs the one-time join token" and systemd restarted it 42 times.
func TestAJoiningSystemNodeWhoseDataWasWipedRefusesOnce(t *testing.T) {
	data := filepath.Join(t.TempDir(), "d")
	cfg := cpConfig(t, data)
	cfg.HostName = "cp2"
	cfg.Store, cfg.Etcd.PeerListen = StoreEtcd, "127.0.0.1:2380"
	cfg.Join = &JoinConfig{Servers: []string{"https://10.0.0.1:6443"}, CA: []byte("not-a-ca"),
		TokenFile: filepath.Join(t.TempDir(), "join-token")}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Start(ctx, cfg)
	var ce *ClusterError
	if !errors.As(err, &ce) {
		t.Fatalf("not a refusal (exit %d): %v", ExitCode(err), err)
	}
	for _, w := range []string{"not starting", "kvoadm host remove cp2", "kvoadm reset", "kvoadm host add cp2 --install control-plane"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("the refusal doesn't say %q:\n%v", w, err)
		}
	}
	if strings.Contains(err.Error(), "kvoadm init creates") {
		t.Errorf("told to make a second cluster:\n%v", err)
	}
	if ExitCode(err) != ExitRefused || ExitRefused == 1 {
		t.Errorf("exit status %d, want %d (not restarted by the unit)", ExitCode(err), ExitRefused)
	}
	if _, statErr := os.Stat(filepath.Join(data, "etcd", "data", "member")); statErr == nil {
		t.Fatal("a store was made anyway")
	}
}

// A first join still has its token: that start is not the wiped-data refusal.
func TestAFirstJoinWithItsTokenIsNotAWipedDataRefusal(t *testing.T) {
	data := filepath.Join(t.TempDir(), "d")
	tok := filepath.Join(t.TempDir(), "join-token")
	if err := os.WriteFile(tok, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := cpConfig(t, data)
	cfg.HostName = "cp2"
	cfg.Store, cfg.Etcd.PeerListen = StoreEtcd, "127.0.0.1:2380"
	cfg.Join = &JoinConfig{Servers: []string{"https://127.0.0.1:1"}, CA: []byte("not-a-ca"), TokenFile: tok}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Start(ctx, cfg)
	var ce *ClusterError
	if errors.As(err, &ce) {
		t.Fatalf("a first join with its token was refused as wiped data: %v", err)
	}
	if err == nil {
		t.Fatal("a join to nowhere succeeded")
	}
}
