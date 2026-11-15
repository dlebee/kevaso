package kic

import (
	"slices"
	"testing"
)

// K-089: what the agent reads a running config with when it has no record of what it applied.
func TestOursAndSections(t *testing.T) {
	if Ours([]byte("user nginx;\nhttp {\n}\n")) {
		t.Error("the image's own config taken for Kevaso's")
	}
	if !Ours([]byte("# "+RenderedBy+"'s nginx ingress driver\n")) || !Ours([]byte("x\n  # ingress a/b\n")) {
		t.Error("Kevaso's config not recognised")
	}
	cfg := "head\nserver {\n    # ingress a/x\n    location / {\n    }\n    # -\n    # ingress b/y\n    one\n    # -\n}\n    # ingress a/x\n    two\n    # -\ntail"
	out, by := Sections([]byte(cfg))
	if out != "head\nserver {\n}\ntail\n" {
		t.Errorf("outside %q", out)
	}
	if !slices.Equal(by["a/x"], []string{"# ingress a/x\nlocation / {\n}\n# -\n", "# ingress a/x\ntwo\n# -\n"}) || !slices.Equal(by["b/y"], []string{"# ingress b/y\none\n# -\n"}) {
		t.Errorf("sections %q", by)
	}
	// An unterminated section stays outside: nothing can match it.
	if out, by := Sections([]byte("a\n# ingress a/x\nb")); out != "a\n# ingress a/x\nb\n" || len(by) != 0 {
		t.Errorf("unterminated: %q %v", out, by)
	}
}
