package local

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"kevaso.com/core/testbed"
)

func TestLocalDriver(t *testing.T) {
	ctx := context.Background()
	var d Driver
	m, err := d.Create(ctx, "a1b2c3d4", testbed.Spec{Role: "self", CPUs: 1, Memory: "1GiB", Disk: "1GiB"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "kvt-a1b2c3d4-self" {
		t.Fatalf("name = %q", m.Name)
	}
	if out, err := d.Exec(ctx, m, "echo", "hi"); err != nil || out != "hi\n" {
		t.Fatalf("Exec = %q, %v", out, err)
	}
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(src, []byte("data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyTo(ctx, m, src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "data" {
		t.Fatalf("copied %q", b)
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}
	if err := d.Delete(ctx, m); err != nil {
		t.Fatal(err)
	}
	if ms, err := d.List(ctx); err != nil || len(ms) != 0 {
		t.Fatalf("List = %v, %v", ms, err)
	}
}

func TestLocalDriverRejectsBadInput(t *testing.T) {
	var d Driver
	if _, err := d.Create(context.Background(), "BAD", testbed.Spec{Role: "self", CPUs: 1, Memory: "1GiB", Disk: "1GiB"}); err == nil {
		t.Fatal("bad run id accepted")
	}
	if _, err := d.Exec(context.Background(), testbed.Machine{}); err == nil {
		t.Fatal("empty command accepted")
	}
}
