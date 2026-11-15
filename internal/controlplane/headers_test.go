package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/backup"
	"kevaso.com/core/internal/kms"
)

// seenBy records what every answer to c said about its control plane.
type seenBy struct {
	mu   sync.Mutex
	all  []client.ControlPlaneSeen
	mark client.Watermark
	last client.Verdict
}

func watch(c *client.Client) *seenBy {
	s := &seenBy{}
	c.ControlPlane = s.hook()
	return s
}

func (s *seenBy) latest(t *testing.T) (client.ControlPlaneSeen, client.Verdict) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.all) == 0 {
		t.Fatal("no answer carried the control plane's identity")
	}
	return s.all[len(s.all)-1], s.last
}

func addNamespaces(t *testing.T, c *client.Client, prefix string, n int) {
	t.Helper()
	for i := range n {
		ns := &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: fmt.Sprintf("%s-%d", prefix, i)}}
		if err := c.Create(context.Background(), ns); err != nil {
			t.Fatal(err)
		}
	}
}

func copyStore(t *testing.T, from, to string) {
	t.Helper()
	for _, f := range []string{"store.db", "store.db-wal", "store.db-shm"} {
		_ = os.Remove(filepath.Join(to, f))
		b, err := os.ReadFile(filepath.Join(from, f))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Every answer, over TLS and the admin socket, says which cluster, which history and how far the
// store has come; the revision only grows across writes and restarts; a store older than the
// one served before (same history) is a Hold for a worker; a deliberate restore is a new history.
func TestEveryAnswerSaysWhichControlPlaneAndHowRecent(t *testing.T) {
	data := t.TempDir()
	cfg := cpConfig(t, data)
	cfg.Create = true
	r, stop := up(t, cfg)
	admin := client.NewUnix(cfg.AdminSocket)
	seen := watch(admin)
	ctx := context.Background()
	var rk client.RecoveryKey
	if err := admin.Call(ctx, http.MethodPost, "/admin/kms/recovery-key", nil, &rk); err != nil {
		t.Fatal(err)
	}
	cp, v := seen.latest(t)
	if cp.ClusterID != r.Cluster.ID || cp.History != r.Cluster.History || cp.Epoch != 1 || cp.Revision < 1 || v != client.Accept {
		t.Fatalf("seen %+v (%s), cluster %+v", cp, v, r.Cluster)
	}
	// TLS too, the way workers talk.
	key, csr, _ := client.NewKeyAndCSR("ops")
	cert, ca, err := admin.SignUserCSR(ctx, "ops", csr)
	if err != nil {
		t.Fatal(err)
	}
	tlsc, err := client.NewTLS("https://"+r.APIAddr, ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	tseen := watch(tlsc)
	var h v1.Host
	_ = tlsc.Get(ctx, "Host", "", "cp-1", &h)
	if tcp, _ := tseen.latest(t); tcp.ClusterID != r.Cluster.ID || tcp.Revision < cp.Revision {
		t.Fatalf("over TLS %+v, before %+v", tcp, cp)
	}
	addNamespaces(t, admin, "a", 3)
	var b client.Backup // a backup from here: older than what follows
	if err := admin.Call(ctx, http.MethodPost, "/admin/backup", nil, &b); err != nil {
		t.Fatal(err)
	}
	stop()
	older := t.TempDir()
	copyStore(t, data, older) // the store as it is now, kept aside

	cfg = cpConfig(t, data)
	_, stop = up(t, cfg) // a plain restart keeps counting up
	admin = client.NewUnix(cfg.AdminSocket)
	admin.ControlPlane = seen.hook()
	addNamespaces(t, admin, "b", 5)
	cp2, v := seen.latest(t)
	if cp2.History != cp.History || cp2.Revision <= cp.Revision || v != client.Accept {
		t.Fatalf("after a restart and writes %+v (%s), before %+v", cp2, v, cp)
	}
	for i := 1; i < len(seen.all); i++ {
		if seen.all[i].Revision < seen.all[i-1].Revision {
			t.Fatalf("the revision went down within one history: %d then %d", seen.all[i-1].Revision, seen.all[i].Revision)
		}
	}
	stop()

	// The system node now serves the older store (it lost what came after): same cluster, same
	// history, a lower revision. It starts (the identity is right), and a worker holds.
	copyStore(t, older, data)
	cfg = cpConfig(t, data)
	_, stop = up(t, cfg)
	admin = client.NewUnix(cfg.AdminSocket)
	admin.ControlPlane = seen.hook()
	var ns v1.Namespace
	_ = admin.Get(ctx, "Namespace", "", "a-0", &ns)
	cp3, v := seen.latest(t)
	if cp3.History != cp.History || cp3.Revision >= cp2.Revision || v != client.Hold {
		t.Fatalf("an older store: %+v (%s), the worker saw %+v", cp3, v, cp2)
	}
	stop()

	// A deliberate restore of the same backup: a new history, which the held worker accepts.
	keyR, _ := kms.ParseRecoveryKey(rk.RecoveryKey)
	fresh := t.TempDir()
	if _, err := backup.Restore(ctx, b.Backup, keyR, fresh); err != nil {
		t.Fatal(err)
	}
	if err := MarkRestored(fresh); err != nil {
		t.Fatal(err)
	}
	fcfg := cpConfig(t, fresh)
	r4, stop4 := up(t, fcfg)
	defer stop4()
	c4 := client.NewUnix(fcfg.AdminSocket)
	c4.ControlPlane = seen.hook()
	_ = c4.Get(ctx, "Namespace", "", "a-0", &ns)
	cp4, v := seen.latest(t)
	if cp4.ClusterID != r.Cluster.ID || cp4.History == cp.History || cp4.Epoch != 2 || cp4.Revision >= cp2.Revision || v != client.NewHistory {
		t.Fatalf("restored: %+v (%s), cluster %+v", cp4, v, r4.Cluster)
	}
}

func (s *seenBy) hook() client.ControlPlaneJudge { return s }

// Sending implements client.ControlPlaneJudge.
func (s *seenBy) Sending() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mark.Revision
}

// Answer implements client.ControlPlaneJudge.
func (s *seenBy) Answer(sent int64, cp client.ControlPlaneSeen) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.all = append(s.all, cp)
	s.mark, s.last = client.JudgeAnswer(s.mark, sent, cp)
}
