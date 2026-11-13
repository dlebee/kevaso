package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"kevaso.com/core/sdk/kplugin"
)

func TestHandlesStayUnderTheRoot(t *testing.T) {
	p := &Plugin{Root: "/srv/hostdir"}
	for _, h := range []string{"../etc", "uid/../../etc", "/abs/x", "uid", "uid/name/extra", "UID/x"} {
		if d, err := p.dir(h); err == nil {
			t.Errorf("handle %q accepted: %s", h, d)
		}
	}
	if d, err := p.dir("0f3a-uid/disk.root"); err != nil || d != "/srv/hostdir/volumes/0f3a-uid/disk.root" {
		t.Errorf("a good handle: %q %v", d, err)
	}
}

func TestEnsureAndDelete(t *testing.T) {
	root := t.TempDir()
	p := &Plugin{Root: root}
	st, err := p.EnsureVolume(context.Background(), kplugin.Volume{Class: Class, ID: "u1/home", SizeBytes: 5})
	if err != nil || st.Handle != "u1/home" || st.SizeEnforced {
		t.Fatalf("ensure: %+v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(root, "volumes/u1/home")); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteVolume(context.Background(), kplugin.VolumeRef{Class: Class, Handle: "u1/home"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "volumes/u1")); !os.IsNotExist(err) {
		t.Errorf("the silo's folder is left: %v", err)
	}
}

func TestUnescape(t *testing.T) {
	if got := unescape(`/a\040b\\x`); got != `/a b\\x` {
		t.Errorf("%q", got)
	}
}

func TestManifestParses(t *testing.T) {
	b, err := os.ReadFile("kevaso-plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kplugin.ParseManifest(b); err != nil {
		t.Fatal(err)
	}
}
