package apiserver

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/refusals.txt")

// The refusals people meet, word for word, as the API answers them (kvo prints them as they
// are): a change in wording shows up as a diff here. When it's meant:
//
//	go test ./internal/apiserver -run TestRefusalMessages -args -update
func TestRefusalMessages(t *testing.T) {
	v, err := newValidator(builtinRules)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{valid: v}
	var b strings.Builder
	for _, c := range refusals {
		err := admitJSON(t, s, c.kind, objectOf(t, c.kind, c.set))
		msg := fmt.Sprint(err)
		if len(msg) > 400 {
			msg = msg[:400] + "…"
		}
		var set []string
		for _, x := range c.set {
			if len(x) > 160 {
				x = x[:160] + "…"
			}
			set = append(set, x)
		}
		fmt.Fprintf(&b, "%s %s\n  %s\n", c.kind, strings.Join(set, " "), msg)
	}
	got := b.String()
	if len(got) > 200<<10 {
		t.Fatal("too long")
	}
	path := filepath.Join("testdata", "refusals.txt")
	if *updateGolden {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -args -update to create it)", err)
	}
	if string(want) != got {
		t.Errorf("refusal messages changed (rerun with -args -update if that's meant): diff testdata/refusals.txt")
	}
}
