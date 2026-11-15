// Command skipbudget reads `go test -json` output on stdin and fails unless every test named in
// the expected file reported PASS. A test that skipped, failed or never ran is a failure: the
// e2e job used to be green while twenty of its twenty-one tests skipped.
//
//	go test -tags e2e -json ./test/e2e/... | go run ./hack/skipbudget test/e2e/ci-expected.txt
//
// The expected file lists one test name per line; blank lines and # comments are ignored. A
// name is a top-level test (TestX) or a subtest (TestX/sub).
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"

	"kevaso.com/core/hack/skipbudget/budget"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: skipbudget EXPECTED_FILE < go-test-json")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "skipbudget:", err)
		os.Exit(2)
	}
	defer func() { _ = f.Close() }() // read-only
	want, err := budget.Expected(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "skipbudget:", err)
		os.Exit(2)
	}
	// Pass the stream through, so the job's log still has the test output.
	problems := budget.Check(io.TeeReader(os.Stdin, os.Stdout), want)
	if len(problems) == 0 {
		fmt.Printf("skipbudget: all %d expected tests passed\n", len(want))
		return
	}
	sort.Strings(problems)
	w := bufio.NewWriter(os.Stderr)
	for _, p := range problems {
		fmt.Fprintln(w, "skipbudget:", p)
	}
	_ = w.Flush()
	os.Exit(1)
}
