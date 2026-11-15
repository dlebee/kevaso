package where

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite test/WHERE.md")

// test/WHERE.md says which tests exist under each build tag and where they run. It is generated
// from the code: adding, renaming or retagging a tagged test, or a fuzzer, changes it, and this
// test fails until `make where` has been run.
func TestWhereIsNotStale(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Generate(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "test", "WHERE.md")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("test/WHERE.md: %v (run `make where`)", err)
	}
	if string(want) != got {
		t.Fatal("test/WHERE.md is stale: run `make where` and commit it")
	}
}

// Every test the CI e2e job is told to expect must exist, or the skip budget would be checking a
// name that nothing can ever report.
func TestTheCIExpectedTestsExist(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Generate(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := "names tests that do not exist"; contains(got, want) {
		t.Fatalf("%s names tests that do not exist: see test/WHERE.md", CIExpectedFile)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
