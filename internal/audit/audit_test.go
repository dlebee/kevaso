package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func lines(t *testing.T, path string) []Entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

func TestFileWritesJSONLinesAndRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "audit.log")
	f := &File{Path: path, MaxBytes: 600}
	for i := 0; i < 6; i++ {
		f.Record(Entry{Time: time.Unix(int64(i), 0).UTC(), User: "bob", Verb: "get", Resource: "silos", Namespace: "payments", Name: "api", Allowed: i%2 == 0, Reason: "RoleBinding payments/bob"})
	}
	_ = f.Close()
	cur, old := lines(t, path), lines(t, path+".1")
	if len(cur)+len(old) != 6 || len(old) == 0 {
		t.Fatalf("%d + %d entries", len(cur), len(old))
	}
	if last := cur[len(cur)-1]; last.Time.Unix() != 5 || last.User != "bob" || last.Allowed {
		t.Fatalf("last entry %+v", last)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	// Reopening appends.
	f2 := &File{Path: path, MaxBytes: 1 << 20}
	f2.Record(Entry{User: "carol"})
	_ = f2.Close()
	if got := lines(t, path); got[len(got)-1].User != "carol" || len(got) != len(cur)+1 {
		t.Fatalf("after reopen: %d", len(got))
	}
}
