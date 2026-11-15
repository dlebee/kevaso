// Package budget judges a `go test -json` stream against a list of tests that must pass.
package budget

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Expected reads the list of test names, one per line (# comments and blank lines ignored).
func Expected(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// Check returns one message per expected test that did not pass: it skipped, failed, or never
// reported (it was not built, or its package did not run). An empty list expects nothing, which
// is itself a problem: a budget that checks no test is no budget.
func Check(stream io.Reader, expected []string) []string {
	if len(expected) == 0 {
		return []string{"the expected list is empty: nothing is checked"}
	}
	final := map[string]string{}
	sc := bufio.NewScanner(stream)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e struct{ Action, Test string }
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Test == "" {
			continue
		}
		switch e.Action {
		case "pass", "fail", "skip":
			final[e.Test] = e.Action
		}
	}
	var out []string
	for _, name := range expected {
		switch got := final[name]; got {
		case "pass":
		case "":
			out = append(out, fmt.Sprintf("%s never ran (not built, filtered out, or its package failed before it)", name))
		default:
			out = append(out, fmt.Sprintf("%s reported %s, and must pass in this job", name, strings.ToUpper(got)))
		}
	}
	return out
}
