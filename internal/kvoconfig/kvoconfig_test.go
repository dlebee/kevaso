package kvoconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAddContextAndClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if c, err := Load(path); err != nil || len(c.Contexts) != 0 {
		t.Fatalf("missing file: %+v %v", c, err)
	}
	// A real CA PEM isn't needed to test storage; Client then fails on parsing, which we check too.
	if err := AddContext(path, "home", "https://203.0.113.10:6443", []byte("ca"), []byte("cert"), []byte("key")); err != nil {
		t.Fatal(err)
	}
	if err := AddContext(path, "lab", "https://198.51.100.7:6443", []byte("ca2"), []byte("cert2"), []byte("key2")); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.CurrentContext != "lab" || len(c.Contexts) != 2 || c.Contexts["home"].Server != "https://203.0.113.10:6443" {
		t.Fatalf("config %+v", c)
	}
	for _, f := range []string{path, c.Contexts["home"].Key} {
		if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v %v, want 0600", f, fi.Mode(), err)
		}
	}
	if _, _, err := c.Client(path, "nope"); err == nil {
		t.Fatal("unknown context accepted")
	}
	if _, _, err := c.Client(path, ""); err == nil {
		t.Fatal("a context with a garbage CA produced a client")
	}
}
