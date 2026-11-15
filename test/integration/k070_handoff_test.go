package integration

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/store"
)

func k070Server(t *testing.T) (*client.Client, func(host, from string) *v1.Silo) {
	t.Helper()
	srv, err := apiserver.New(store.NewMemory(0), clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	c := client.New(ts.URL)
	ctx := context.Background()
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}); err != nil {
		t.Fatal(err)
	}
	n := 0
	placed := func(host, from string) *v1.Silo {
		t.Helper()
		n++
		s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "s" + string(rune('0'+n)), Namespace: "d"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Availability: v1.Availability{OnHostLoss: v1.OnHostLossRecreate}}}
		if err := c.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host, s.Status.MovingFrom, s.Status.Phase = host, from, "Running"
		if err := c.UpdateStatus(ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	return c, placed
}

// drainTo is what kvoadm host drain writes (DrainStatus): placed afresh, handed off from host.
func drainTo(host string) func(*v1.Silo) (v1.SiloStatus, error) {
	return func(s *v1.Silo) (v1.SiloStatus, error) {
		st := s.Status
		st.Host, st.Phase, st.MovingFrom = "", "Pending", host
		return st, nil
	}
}

// K-070: starting a handoff is refused while one is under way, whatever the caller read: the
// client reads the silo afresh and writes at the version it read.
func TestK070StartHandoffIsRefusedWhileOneIsUnderWay(t *testing.T) {
	ctx := context.Background()
	c, placed := k070Server(t)

	// S → D under way; drain D.
	s := placed("D", "S")
	_, err := c.StartHandoff(ctx, s, drainTo("D"))
	if !errors.Is(err, client.ErrHandoffUnderWay) {
		t.Fatalf("drain of a handoff's destination: %v, want ErrHandoffUnderWay", err)
	}
	var got v1.Silo
	if err := c.Get(ctx, "Silo", "d", s.Name, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.MovingFrom != "S" || got.Status.Host != "D" {
		t.Fatalf("the handoff was overwritten: host %q movingFrom %q", got.Status.Host, got.Status.MovingFrom)
	}

	// The caller read it before the move began (a stale list): still refused.
	stale := placed("D", "")
	moved := *stale
	moved.Status.Host, moved.Status.MovingFrom = "E", "D"
	if err := c.UpdateStatus(ctx, &moved); err != nil {
		t.Fatal(err)
	}
	if _, err := c.StartHandoff(ctx, stale, drainTo("E")); !errors.Is(err, client.ErrHandoffUnderWay) {
		t.Fatalf("drain from a stale read: %v, want ErrHandoffUnderWay", err)
	}

	// No handoff: it starts, at the version read.
	free := placed("D", "")
	out, err := c.StartHandoff(ctx, free, drainTo("D"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Status.MovingFrom != "D" || out.Status.Host != "" {
		t.Fatalf("drain wrote host %q movingFrom %q", out.Status.Host, out.Status.MovingFrom)
	}
	// Placed on E later, E may not start it before D lets go.
	out.Status.Host = "E"
	if moves.MayStart(out, "E") {
		t.Fatal("E may start it before D lets go")
	}
}

// A move that lands between the client's read and its write: the write conflicts, the client
// reads again, sees the handoff and refuses. Deterministic: the move is made inside the
// status function, which runs between the read and the write.
func TestK070AMoveBetweenReadAndWriteIsNotOverwritten(t *testing.T) {
	ctx := context.Background()
	c, placed := k070Server(t)
	s := placed("D", "")
	calls := 0
	_, err := c.StartHandoff(ctx, s, func(cur *v1.Silo) (v1.SiloStatus, error) {
		calls++
		if calls == 1 {
			m := *cur
			m.Status.Host, m.Status.MovingFrom = "E", "D" // kvo move D → E lands now
			if err := c.UpdateStatus(ctx, &m); err != nil {
				t.Fatal(err)
			}
		}
		return drainTo("D")(cur)
	})
	if !errors.Is(err, client.ErrHandoffUnderWay) {
		t.Fatalf("after a racing move: %v (status function called %d times), want ErrHandoffUnderWay", err, calls)
	}
	var got v1.Silo
	if err := c.Get(ctx, "Silo", "d", s.Name, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Host != "E" || got.Status.MovingFrom != "D" {
		t.Fatalf("the racing move was overwritten: host %q movingFrom %q", got.Status.Host, got.Status.MovingFrom)
	}
}

// A silo deleted and made again under the same name is not the one the caller decided on.
func TestK070StartHandoffIsForTheSiloRead(t *testing.T) {
	ctx := context.Background()
	c, placed := k070Server(t)
	s := placed("D", "")
	other := *s
	other.UID = "someone-else"
	if _, err := c.StartHandoff(ctx, &other, drainTo("D")); !client.IsConflict(err) {
		t.Fatalf("another UID under the name: %v, want a Conflict", err)
	}
}
