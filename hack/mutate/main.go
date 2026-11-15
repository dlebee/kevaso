// Command mutate checks that the safety guards listed in mutations.json cannot be removed
// without a test failing. For each mutation it rewrites one line of product code in a temporary
// file, hands the Go toolchain an overlay (go test -overlay) so the working tree is never
// touched, runs the named packages' tests, and reports "killed" (a test failed) or "SURVIVED"
// (every test passed with the guard gone or inverted). A mutation that does not compile is
// reported as "invalid": fix its text.
//
//	go run ./hack/mutate                 # every mutation
//	go run ./hack/mutate -id G-001,G-002 # some
//	go run ./hack/mutate -j 4            # four at a time
//
// Exit status is 1 when anything survived or was invalid.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type mutation struct {
	ID       string   `json:"id"`
	Guard    string   `json:"guard"`
	File     string   `json:"file"`
	Find     string   `json:"find"`    // the exact text to change; must occur once in File
	Replace  string   `json:"replace"` // what it becomes
	Mutation string   `json:"mutation"`
	Packages []string `json:"packages"`
	Protects string   `json:"protects"` // the safety property
	// Known: why a survivor is accepted (another layer repeats the guard so the behaviour is the
	// same, or a product seam is missing). A survivor with no reason is a failure.
	Known string `json:"known,omitempty"`
}

type result struct {
	m      mutation
	status string // killed | SURVIVED | invalid
	failed string // the first failing test, or the compile error
	line   int
}

func main() { os.Exit(run()) }

func run() int {
	ids := flag.String("id", "", "comma-separated mutation ids (default: all)")
	jobs := flag.Int("j", 2, "mutations run at once")
	file := flag.String("f", "hack/mutate/mutations.json", "the mutations")
	runPat := flag.String("run", "", "go test -run pattern (to check one new test quickly)")
	only := flag.String("pkgs", "", "space-separated packages, instead of each mutation's own")
	check := flag.Bool("check", false, "only check that every entry's find text occurs exactly once in its file; no tests run")
	flag.Parse()
	raw, err := os.ReadFile(*file)
	if err != nil {
		return fatal(err)
	}
	var all []mutation
	if err := json.Unmarshal(raw, &all); err != nil {
		return fatal(err)
	}
	want := map[string]bool{}
	for _, id := range strings.Split(*ids, ",") {
		if id != "" {
			want[id] = true
		}
	}
	root, _ := os.Getwd()
	if *check {
		stale := Stale(root, all)
		if len(stale) > 0 {
			fmt.Fprintf(os.Stderr, "mutate: %d stale entries in %s (the code they mutate has moved; update them):\n  %s\n", len(stale), *file, strings.Join(stale, "\n  "))
			return 1
		}
		fmt.Printf("mutate: all %d entries match their code exactly once\n", len(all))
		return 0
	}
	tmp, err := os.MkdirTemp("", "kevaso-mutate-")
	if err != nil {
		return fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	var run []mutation
	for _, m := range all {
		if len(want) == 0 || want[m.ID] {
			run = append(run, m)
		}
	}
	results := make([]result, len(run))
	sem := make(chan struct{}, *jobs)
	var wg sync.WaitGroup
	for i, m := range run {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = try(root, tmp, m, *runPat, *only)
			fmt.Fprintf(os.Stderr, "%-6s %-9s %s\n", m.ID, results[i].status, results[i].failed)
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].m.ID < results[j].m.ID })
	bad := 0
	fmt.Println("| id | guard | file:line | mutation | result | first failing test |")
	fmt.Println("|---|---|---|---|---|---|")
	for _, r := range results {
		if r.status == "SURVIVED" && r.m.Known != "" {
			r.status = "known: " + r.m.Known
		} else if r.status != "killed" {
			bad++
		}
		fmt.Printf("| %s | %s | %s:%d | %s | %s | %s |\n", r.m.ID, r.m.Guard, r.m.File, r.line, r.m.Mutation, r.status, r.failed)
	}
	fmt.Printf("\n%d mutations, %d killed, %d not\n", len(results), len(results)-bad, bad)
	if bad > 0 {
		return 1
	}
	return 0
}

// Stale lists the entries whose find text does not occur exactly once in its file under root,
// each as "G-005 internal/agent/agent.go: occurs 0 times (want 1)". Empty when the list is current.
func Stale(root string, all []mutation) []string {
	var out []string
	for _, m := range all {
		src, err := os.ReadFile(filepath.Join(root, m.File))
		if err != nil {
			out = append(out, fmt.Sprintf("%s %s: %v", m.ID, m.File, err))
			continue
		}
		if m.Find == "" {
			out = append(out, fmt.Sprintf("%s %s: empty find text", m.ID, m.File))
		} else if n := bytes.Count(src, []byte(m.Find)); n != 1 {
			out = append(out, fmt.Sprintf("%s %s: find text occurs %d times (want 1): %q", m.ID, m.File, n, firstLine(m.Find)))
		}
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + "..."
	}
	return s
}

func try(root, tmp string, m mutation, runPat, only string) result {
	r := result{m: m}
	src, err := os.ReadFile(filepath.Join(root, m.File))
	if err != nil {
		r.status, r.failed = "invalid", err.Error()
		return r
	}
	if n := bytes.Count(src, []byte(m.Find)); n != 1 {
		r.status, r.failed = "invalid", fmt.Sprintf("find text occurs %d times in %s, want once", n, m.File)
		return r
	}
	idx := bytes.Index(src, []byte(m.Find))
	r.line = 1 + bytes.Count(src[:idx], []byte("\n"))
	out := bytes.Replace(src, []byte(m.Find), []byte(m.Replace), 1)
	dir := filepath.Join(tmp, m.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.status, r.failed = "invalid", err.Error()
		return r
	}
	mutated := filepath.Join(dir, filepath.Base(m.File))
	if err := os.WriteFile(mutated, out, 0o644); err != nil {
		r.status, r.failed = "invalid", err.Error()
		return r
	}
	ov, _ := json.Marshal(map[string]map[string]string{"Replace": {filepath.Join(root, m.File): mutated}})
	ovPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(ovPath, ov, 0o644); err != nil {
		r.status, r.failed = "invalid", err.Error()
		return r
	}
	pkgs := m.Packages
	if only != "" {
		pkgs = strings.Fields(only)
	}
	args := []string{"test", "-count=1", "-overlay=" + ovPath, "-failfast", "-timeout=10m", "-json"}
	if runPat != "" {
		args = append(args, "-run", runPat)
	}
	args = append(args, pkgs...)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	b, _ := cmd.CombinedOutput()
	r.status, r.failed = verdict(b)
	return r
}

// verdict reads go test -json output: the first test that failed, or a build failure (the
// mutation does not compile: "invalid", not a kill).
func verdict(b []byte) (string, string) {
	type ev struct {
		Action, Package, Test, Output string
	}
	var built, pkgFailed string
	for _, line := range strings.Split(string(b), "\n") {
		var e ev
		if json.Unmarshal([]byte(line), &e) != nil {
			if strings.Contains(line, "[build failed]") || strings.Contains(line, "[setup failed]") {
				built = strings.TrimSpace(line)
			} else if built == "" && strings.Contains(line, ".go:") {
				pkgFailed = strings.TrimSpace(line) // a compiler message
			}
			continue
		}
		if strings.Contains(e.Output, "[build failed]") || strings.Contains(e.Output, "[setup failed]") {
			built = strings.TrimSpace(e.Output)
		}
		if e.Action == "fail" && e.Test != "" {
			return "killed", e.Package[strings.LastIndex(e.Package, "/")+1:] + "." + e.Test
		}
		if e.Action == "fail" && e.Test == "" {
			pkgFailed = "package " + e.Package + " failed"
		}
	}
	switch {
	case built != "":
		return "invalid", built + " " + pkgFailed
	case pkgFailed != "":
		// No test failed but the package did: a panic, a crash or a timeout the mutation caused.
		return "killed", pkgFailed + " (package-level: panic, timeout or exit)"
	}
	return "SURVIVED", ""
}

func fatal(err error) int {
	fmt.Fprintln(os.Stderr, "mutate:", err)
	return 2
}
