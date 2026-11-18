package openshell

import "testing"

func TestCanonicalImageRebuildsTheReference(t *testing.T) {
	got, err := canonicalImage("GHCR.IO/acme/api:V1")
	if err != nil || got != "ghcr.io/acme/api:V1" {
		t.Fatalf("canonical image %q %v", got, err)
	}
	if got, err := canonicalImage(""); err != nil || got != "" {
		t.Fatalf("default image %q %v", got, err)
	}
	if got, err := canonicalImage("ubuntu-24.04"); err != nil || got != "" {
		t.Fatalf("built-in image %q %v", got, err)
	}
}

func TestCanonicalImageRefusesAnArchive(t *testing.T) {
	if _, err := canonicalImage("var/lib/x/foo.tar"); err == nil {
		t.Fatal("a rootfs archive was accepted as an image")
	}
	if _, err := canonicalImage("ghcr.io/acme/root.tar.gz"); err == nil {
		t.Fatal("a gzipped rootfs archive was accepted as an image")
	}
}
