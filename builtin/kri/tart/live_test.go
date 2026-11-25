//go:build tartlive

package tart

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

// Run on an Apple Silicon Mac with Tart installed and the image already pulled (a pull is tens
// of GB and hours: tart pull IMAGE first):
//
//	TART_TEST_IMAGE=ghcr.io/cirruslabs/macos-tahoe-base:latest go test -tags tartlive -run Live -v ./builtin/kri/tart
//
// It drives the real tart through the runtime: create, start (the first exec answers), exec with
// an exit code and stdin, stop, start again, reset, delete. Two silos run at once and a third is
// refused. Everything it makes is deleted, even when it fails.
func TestLiveLifecycleAndLimit(t *testing.T) {
	image := os.Getenv("TART_TEST_IMAGE")
	if image == "" {
		t.Skip("set TART_TEST_IMAGE to a pulled macOS image")
	}
	hostexec.SetCommandParent(t.TempDir()) // kevasod is root and uses /var/run/kevaso; this test is not
	r := &Runtime{Host: Local{}, StateDir: t.TempDir(), PullWait: time.Second}
	ctx := context.Background()
	if err := r.Install(ctx, func(s string) { t.Log(s) }); err != nil {
		t.Fatal(err)
	}
	mk := func(n string) kri.Spec {
		return kri.Spec{ID: kri.ID{Namespace: "live", Name: n, UID: "t" + n}, Image: image, CPU: 4, Memory: 8 << 30}
	}
	var made []kri.ID
	t.Cleanup(func() {
		for _, id := range made {
			if err := r.Delete(context.Background(), id); err != nil {
				t.Errorf("cleanup %v: %v", id, err)
			}
		}
	})
	for _, n := range []string{"a", "b", "c"} {
		made = append(made, mk(n).ID)
		if err := r.Create(ctx, mk(n)); err != nil {
			t.Fatal(err)
		}
	}
	a := mk("a").ID
	t0 := time.Now()
	if err := r.Start(ctx, a); err != nil {
		t.Fatal(err)
	}
	t.Logf("start to first exec: %s", time.Since(t0).Round(time.Second))
	if st, _ := r.Status(ctx, a); st.State != kri.Running || st.Address != "" {
		t.Fatalf("%+v", st)
	}
	var out bytes.Buffer
	if code, err := r.Exec(ctx, a, kri.ExecRequest{Command: []string{"cat"}, Stdin: strings.NewReader("hello"), Stdout: &out}); err != nil || code != 0 || out.String() != "hello" {
		t.Fatalf("stdin: %d %v %q", code, err, out.String())
	}
	if code, err := r.Exec(ctx, a, kri.ExecRequest{Command: []string{"sh", "-c", "exit 7"}}); err != nil || code != 7 {
		t.Fatalf("exit code: %d %v", code, err)
	}
	if err := r.Start(ctx, mk("b").ID); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, mk("c").ID); err != ErrCapacity {
		t.Fatalf("the third macOS silo must be refused: %v", err)
	}
	if err := r.Stop(ctx, a); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.Status(ctx, a); st.State != kri.Stopped {
		t.Fatalf("%+v", st)
	}
	if err := r.Start(ctx, mk("c").ID); err != nil {
		t.Fatalf("after a stop the third fits: %v", err)
	}
	if err := r.Reset(ctx, mk("a")); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.Status(ctx, a); st.State != kri.Created {
		t.Fatalf("after reset: %+v", st)
	}
}
