// Package kritest is the conformance suite for kri.Runtime: every runtime, real or fake, must pass
// it. Real runtimes run it on a machine that can host them (Lima, the CI runner); the fake runs it
// in unit tests.
package kritest

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"kevaso.com/core/sdk/kri"
)

// Options tune the suite for a runtime.
type Options struct {
	Image   string        // an image the runtime can boot
	Timeout time.Duration // per test; real VMs need minutes
}

// Run runs the suite. newRuntime returns a runtime with no silos.
func Run(t *testing.T, newRuntime func(t *testing.T) kri.Runtime, o Options) {
	if o.Timeout == 0 {
		o.Timeout = time.Minute
	}
	ctxT := func(t *testing.T) context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
		t.Cleanup(cancel)
		return ctx
	}
	spec := func(name string) kri.Spec {
		return kri.Spec{ID: kri.ID{Namespace: "kritest", Name: name, UID: "uid-" + name}, Image: o.Image,
			CPU: 1, Memory: 512 << 20, DiskBytes: 4 << 30}
	}
	cleanup := func(t *testing.T, r kri.Runtime, id kri.ID) {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
			defer cancel()
			_ = r.Delete(ctx, id)
		})
	}

	t.Run("InfoReportsCapabilities", func(t *testing.T) {
		info := newRuntime(t).Info()
		if info.Name == "" || info.Capabilities.Isolation == "" || info.Capabilities.Persistence == "" {
			t.Fatalf("incomplete info %+v", info)
		}
	})

	t.Run("Lifecycle", func(t *testing.T) {
		r, ctx, s := newRuntime(t), ctxT(t), spec("life")
		cleanup(t, r, s.ID)
		if st, err := r.Status(ctx, s.ID); err != nil || st.State != kri.Absent {
			t.Fatalf("before create: %+v %v", st, err)
		}
		if err := r.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := r.Create(ctx, s); err != nil {
			t.Fatalf("create is idempotent, second call: %v", err)
		}
		if err := r.Start(ctx, s.ID); err != nil {
			t.Fatal(err)
		}
		if err := r.Start(ctx, s.ID); err != nil {
			t.Fatalf("start is idempotent, second call: %v", err)
		}
		if st, err := r.Status(ctx, s.ID); err != nil || st.State != kri.Running {
			t.Fatalf("after start: %+v %v", st, err)
		}
		if err := r.Stop(ctx, s.ID); err != nil {
			t.Fatal(err)
		}
		if st, _ := r.Status(ctx, s.ID); st.State != kri.Stopped {
			t.Fatalf("after stop: %+v", st)
		}
		if err := r.Start(ctx, s.ID); err != nil {
			t.Fatalf("restart after stop: %v", err)
		}
		if err := r.Delete(ctx, s.ID); err != nil {
			t.Fatal(err)
		}
		if err := r.Delete(ctx, s.ID); err != nil {
			t.Fatalf("delete is idempotent, second call: %v", err)
		}
		if st, _ := r.Status(ctx, s.ID); st.State != kri.Absent {
			t.Fatalf("after delete: %+v", st)
		}
	})

	t.Run("ListShowsOnlyLiveSilos", func(t *testing.T) {
		r, ctx := newRuntime(t), ctxT(t)
		a, b := spec("list-a"), spec("list-b")
		cleanup(t, r, a.ID)
		cleanup(t, r, b.ID)
		_ = r.Create(ctx, a)
		_ = r.Create(ctx, b)
		_ = r.Delete(ctx, a.ID)
		ids, err := r.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, id := range ids {
			found[id.Name] = true
		}
		if found["list-a"] || !found["list-b"] {
			t.Fatalf("list %v", ids)
		}
	})

	t.Run("Exec", func(t *testing.T) {
		r, ctx, s := newRuntime(t), ctxT(t), spec("exec")
		cleanup(t, r, s.ID)
		if _, err := r.Exec(ctx, s.ID, kri.ExecRequest{Command: []string{"true"}}); err == nil {
			t.Fatal("exec in an absent silo succeeded")
		}
		_ = r.Create(ctx, s)
		_ = r.Start(ctx, s.ID)
		var out bytes.Buffer
		code, err := r.Exec(ctx, s.ID, kri.ExecRequest{Command: []string{"echo", "hello"}, Stdout: &out})
		if err != nil || code != 0 || out.String() != "hello\n" {
			t.Fatalf("echo: code %d out %q err %v", code, out.String(), err)
		}
		code, err = r.Exec(ctx, s.ID, kri.ExecRequest{Command: []string{"sh", "-c", "exit 3"}})
		if err != nil || code != 3 {
			t.Fatalf("exit 3: code %d err %v", code, err)
		}
	})

	t.Run("ResetKeepsTheAddress", func(t *testing.T) {
		r, ctx, s := newRuntime(t), ctxT(t), spec("reset")
		rr, ok := r.(kri.Resetter)
		if !ok {
			t.Skip("not a Resetter")
		}
		cleanup(t, r, s.ID)
		if err := r.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := r.Start(ctx, s.ID); err != nil {
			t.Fatal(err)
		}
		before, _ := r.Status(ctx, s.ID)
		if err := r.Stop(ctx, s.ID); err != nil {
			t.Fatal(err)
		}
		if err := rr.Reset(ctx, s); err != nil {
			t.Fatal(err)
		}
		if st, err := r.Status(ctx, s.ID); err != nil || st.State != kri.Created {
			t.Fatalf("after reset: %+v %v (want Created)", st, err)
		}
		if err := r.Start(ctx, s.ID); err != nil {
			t.Fatal(err)
		}
		if after, _ := r.Status(ctx, s.ID); after.State != kri.Running || after.Address != before.Address {
			t.Fatalf("after reset and start: %+v, before %+v (same address)", after, before)
		}
		if err := rr.Reset(ctx, spec("never-made")); !errors.Is(err, kri.ErrNotFound) {
			t.Fatalf("reset of an absent silo: want ErrNotFound, got %v", err)
		}
	})

	t.Run("OperationsOnAbsentSilos", func(t *testing.T) {
		r, ctx := newRuntime(t), ctxT(t)
		id := spec("absent").ID
		for name, err := range map[string]error{"start": r.Start(ctx, id), "stop": r.Stop(ctx, id)} {
			if !errors.Is(err, kri.ErrNotFound) {
				t.Errorf("%s on an absent silo: want ErrNotFound, got %v", name, err)
			}
		}
	})
}
