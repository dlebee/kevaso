package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryMutationStillMatchesItsCode fails, naming the entries, when a guard moved and its
// mutation would silently apply to nothing (or to two places). Fast: it only reads files.
func TestEveryMutationStillMatchesItsCode(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("mutations.json")
	if err != nil {
		t.Fatal(err)
	}
	var all []mutation
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("mutations.json lists nothing")
	}
	seen := map[string]bool{}
	for _, m := range all {
		if seen[m.ID] {
			t.Errorf("%s is listed twice", m.ID)
		}
		seen[m.ID] = true
		if m.Replace == m.Find {
			t.Errorf("%s: replace equals find, the mutation changes nothing", m.ID)
		}
		if len(m.Packages) == 0 {
			t.Errorf("%s: no packages to test", m.ID)
		}
	}
	if stale := Stale(root, all); len(stale) > 0 {
		t.Errorf("%d stale mutation entries in hack/mutate/mutations.json (update find/replace to the current code):\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}
