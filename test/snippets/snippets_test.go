// Package snippets checks every shell snippet Kevaso runs on a host or in a silo, found in the
// source itself: each `sh -c SCRIPT` (and bash, and -ec…) whose script is a constant is parsed
// with sh -n; none may match a process by a name pgrep/pkill -x can never see (the kernel keeps
// 15 characters of it); and every call to a package manager must be in a file that takes the
// shared install lock (two runtimes installing at once fight over apt's lock). These are the
// general forms of bugs the first runs on real machines found.
//
// A new snippet site (file and function) must be added to sites below, so it's looked at once.
package snippets

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/keep"
)

const module = "kevaso.com/core/"

// sites are the places a shell snippet is run from, by file and function: what it is.
// Dynamic ones (the script is built at run time) say how they're covered.
var sites = map[string]string{
	"builtin/kri/cloudhypervisor/volumes.go MountGuestVolumes": "dynamic: GuestMountScript (rendered below)",
	"builtin/kri/container/install.go Install":                 "apt-get update and install of the engine",
	"builtin/kri/container/runtime.go RunInit":                 "dynamic: a silo's own init step (spec.init), the user's script",
	"builtin/kri/hostexec/sweep.go Held":                       "holdScript: holds a sandbox's processes",
	"builtin/kri/openshell/install.go Install":                 "docker check, apt-get install of docker and the gateway",
	"builtin/kri/openshell/runtime.go Exec":                    "hostexec.SweepScript in the sandbox",
	"internal/agent/agent.go command":                          "dynamic: a silo's own init step",
	"internal/agent/deliveries.go execIn":                      "a constant script, dynamic arguments",
	"internal/apiserver/silostreams.go ":                       "LoginShell",
	"internal/ingress/apply.go ListCmd":                        "listScript",
	"internal/ingress/apply.go WriteCmd":                       "writeScript",
	"internal/keep/keep.go StartCommand":                       "dynamic: a silo's own daemon (rendered below)",
	"internal/keep/keep.go ProbeCommand":                       "dynamic: pid and exit file paths (rendered below)",
	"internal/keep/keep.go StopCommand":                        "dynamic: pid and exit file paths (rendered below)",
	"internal/keep/keep.go CheckCommand":                       "dynamic: a silo's own upkeep check (rendered below)",
	"internal/keep/keep.go FixCommand":                         "dynamic: a silo's own upkeep fix (rendered below)",
	"sdk/kri/kritest/kritest.go Run":                           "the runtime conformance suite's exit 3",
	// On phase/metal and phase/env-shim, listed ahead so the merge keeps this passing.
	"builtin/kri/cloudhypervisor/install.go installPackages": "apt through hostpkg (phase/metal)",
	"builtin/kri/container/install.go installPackages":       "apt through hostpkg (phase/metal)",
	"builtin/kri/container/install.go installDocker":         "docker's own install (phase/metal, phase/env-shim)",
	"builtin/kri/container/install.go realDockerRuntime":     "the engine's runtime path (phase/metal, phase/env-shim)",
}

// unlocked are package-manager calls known to run without the shared lock, by file, and who
// fixes them (reported, not fixed here: these files are another branch's). Once fixed, the
// entry is only logged.
var unlocked = map[string]string{}

type snippet struct {
	site, pos, script string
	static            bool
}

type pkgScan struct {
	consts map[string]ast.Expr // package-level string consts and vars
}

// root is the repo's root (KEVASO_SNIPPETS_ROOT: another tree, e.g. a branch exported to check it).
func root(t *testing.T) string {
	if r := os.Getenv("KEVASO_SNIPPETS_ROOT"); r != "" {
		return r
	}
	r, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// scan parses every non-test Go file of the repo (and the api and sdk modules).
func scan(t *testing.T) (map[string]*pkgScan, map[string]*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs := map[string]*pkgScan{}
	files := map[string]*ast.File{}
	r := root(t)
	err := filepath.WalkDir(r, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == "bin" || d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(r, p)
		files[rel] = f
		dir := filepath.Dir(rel)
		ps := pkgs[dir]
		if ps == nil {
			ps = &pkgScan{consts: map[string]ast.Expr{}}
			pkgs[dir] = ps
		}
		for _, decl := range f.Decls {
			g, ok := decl.(*ast.GenDecl)
			if !ok || (g.Tok != token.CONST && g.Tok != token.VAR) {
				continue
			}
			for _, sp := range g.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						ps.consts[n.Name] = vs.Values[i]
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return pkgs, files, fset
}

// eval is a constant string expression's value (ok false: not constant here).
func eval(e ast.Expr, dir string, imports map[string]string, pkgs map[string]*pkgScan, depth int) (string, bool) {
	if depth > 10 {
		return "", false
	}
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		a, ok1 := eval(x.X, dir, imports, pkgs, depth+1)
		b, ok2 := eval(x.Y, dir, imports, pkgs, depth+1)
		return a + b, ok1 && ok2
	case *ast.ParenExpr:
		return eval(x.X, dir, imports, pkgs, depth+1)
	case *ast.Ident:
		if ps := pkgs[dir]; ps != nil {
			if v, ok := ps.consts[x.Name]; ok {
				return eval(v, dir, imports, pkgs, depth+1)
			}
		}
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			if d, ok := imports[id.Name]; ok {
				if ps := pkgs[d]; ps != nil {
					if v, ok := ps.consts[x.Sel.Name]; ok {
						return eval(v, d, nil, pkgs, depth+1)
					}
				}
			}
		}
	}
	return "", false
}

func importsOf(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if !strings.HasPrefix(p, module) {
			continue
		}
		dir := strings.TrimPrefix(p, module)
		name := filepath.Base(dir)
		if im.Name != nil {
			name = im.Name.Name
		}
		out[name] = dir
	}
	return out
}

var shells = map[string]bool{"sh": true, "/bin/sh": true, "bash": true, "/bin/bash": true}
var cFlags = map[string]bool{"-c": true, "-ec": true, "-euc": true, "-exc": true, "-eu": false}
var pkgManagers = map[string]bool{"apt-get": true, "apt": true, "dpkg": true, "yum": true, "dnf": true, "apk": true, "zypper": true}

type found struct {
	literals []snippet // every string literal or constant naming pgrep or pkill
	snippets []snippet
	pkgCalls map[string][]string // file → positions
	pgrep    []string            // problems
}

func collect(t *testing.T) found {
	pkgs, files, fset := scan(t)
	out := found{pkgCalls: map[string][]string{}}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, rel := range names {
		f := files[rel]
		dir := filepath.Dir(rel)
		imports := importsOf(f)
		var fn string
		seq := func(list []ast.Expr, composite bool, pos token.Pos) {
			var vals []string
			var oks []bool
			for _, e := range list {
				v, ok := eval(e, dir, imports, pkgs, 0)
				vals, oks = append(vals, v), append(oks, ok)
			}
			for i := range list {
				if oks[i] && pkgManagers[vals[i]] {
					out.pkgCalls[rel] = append(out.pkgCalls[rel], fset.Position(list[i].Pos()).String())
				}
				if oks[i] && (vals[i] == "pgrep" || vals[i] == "pkill") {
					for j := i + 1; j+1 < len(list); j++ {
						if oks[j] && vals[j] == "-x" && oks[j+1] && len(vals[j+1]) > 15 {
							out.pgrep = append(out.pgrep, fset.Position(list[j+1].Pos()).String()+": "+vals[i]+" -x "+strconv.Quote(vals[j+1]))
						}
					}
				}
				if !oks[i] || !cFlags[vals[i]] || i+1 >= len(list) {
					continue
				}
				shellBefore := i > 0 && oks[i-1] && shells[vals[i-1]]
				variableShell := i > 0 && !oks[i-1]
				if !shellBefore && (!composite || i != 0) && !variableShell {
					continue
				}
				if variableShell && oks[i+1] && !strings.ContainsAny(vals[i+1], " ;|&$") {
					continue // e.g. a flag's value, not a script
				}
				out.snippets = append(out.snippets, snippet{site: rel + " " + fn, pos: fset.Position(list[i+1].Pos()).String(), script: vals[i+1], static: oks[i+1]})
			}
			// Snippets as plain constants with their own pkg-manager words are checked below.
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if b, ok := n.(*ast.BasicLit); ok && b.Kind == token.STRING && strings.Contains(b.Value, "pgrep") || ok && strings.Contains(b.Value, "pkill") {
				if v, err := strconv.Unquote(b.Value); err == nil {
					out.literals = append(out.literals, snippet{site: rel, pos: fset.Position(b.Pos()).String(), script: v, static: true})
				}
			}
			return true
		})
		for _, decl := range f.Decls {
			fn = ""
			if fd, ok := decl.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					seq(x.Args, false, x.Pos())
				case *ast.CompositeLit:
					seq(x.Elts, true, x.Pos())
				}
				return true
			})
		}
		// Constant scripts that call a package manager (Update lines, install scripts).
		for name, v := range pkgs[dir].consts {
			s, ok := eval(v, dir, imports, pkgs, 0)
			if ok && fset.Position(v.Pos()).Filename == filepath.Join(root(t), rel) && strings.Contains(s, " ") && pkgWord(s) {
				out.pkgCalls[rel] = append(out.pkgCalls[rel], fset.Position(v.Pos()).String()+" ("+name+")")
			}
		}
	}
	return out
}

var pkgRE = regexp.MustCompile(`(^|[\s;&|(])(apt-get|apt|dpkg|yum|dnf|apk|zypper)(\s|$)`)

func pkgWord(s string) bool { return pkgRE.MatchString(s) }

// pgrepProblem says what's wrong with the pgrep -x / pkill -x in a script: the kernel keeps 15
// characters of a process's name, so a longer name never matches, and a name from a variable
// must be cut to 15 (printf %.15s) to match one that's longer.
func pgrepProblem(s string) string {
	for _, m := range pgrepRE.FindAllStringSubmatch(s, -1) {
		name := m[2] + m[3] + m[4]
		switch {
		case strings.Contains(name, "$") && !strings.Contains(name, "%.15s"):
			return fmt.Sprintf("%s -x %s: a name from a variable, not cut to 15 characters (printf %%.15s): a longer one never matches", m[1], name)
		case !strings.Contains(name, "$") && len(name) > 15:
			return fmt.Sprintf("%s -x %q: process names are cut to 15 characters, so it never matches", m[1], name)
		}
	}
	return ""
}

var pgrepRE = regexp.MustCompile(`\b(pgrep|pkill)\b[^|;&\n]*?\s-x\s+(?:'([^']*)'|"([^"]*)"|([^\s;|&]+))`)

func TestEveryHostSnippet(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	got := collect(t)
	if len(got.snippets) < 10 {
		t.Fatalf("found only %d snippets: the scan is broken", len(got.snippets))
	}
	seen := map[string]bool{}
	for _, s := range got.snippets {
		seen[s.site] = true
		if _, ok := sites[s.site]; !ok {
			t.Errorf("%s: a shell snippet in %s that the table doesn't list: add it to sites (and check it)", s.pos, s.site)
		}
		if !s.static {
			continue
		}
		if out, err := exec.Command("sh", "-n", "-c", s.script).CombinedOutput(); err != nil {
			t.Errorf("%s: sh -n: %v: %s\n%s", s.pos, err, out, s.script)
		}
		for _, m := range pgrepRE.FindAllStringSubmatch(s.script, -1) {
			name := m[2] + m[3] + m[4]
			if len(name) > 15 {
				t.Errorf("%s: %s -x %q: process names are cut to 15 characters, so it never matches", s.pos, m[1], name)
			}
		}
		if pkgWord(s.script) {
			rel := strings.SplitN(s.site, " ", 2)[0]
			got.pkgCalls[rel] = append(got.pkgCalls[rel], s.pos)
		}
	}
	for site, note := range sites {
		if !seen[site] && !strings.Contains(note, "(phase/") {
			t.Logf("sites lists %q, which runs no snippet now: drop it", site)
		}
	}
	for _, l := range got.literals {
		if why := pgrepProblem(l.script); why != "" {
			t.Errorf("%s: %s", l.pos, why)
		}
	}
	for _, p := range got.pgrep {
		t.Errorf("%s: process names are cut to 15 characters, so it never matches", p)
	}
	_, files, _ := scan(t)
	for rel, at := range got.pkgCalls {
		if strings.HasPrefix(rel, "internal/cli/kvoadm/check.go") || strings.Contains(rel, "hostpkg") {
			continue // the host check only asks whether apt-get exists; hostpkg is the lock itself
		}
		if takesLock(files[rel]) {
			continue
		}
		if who, ok := unlocked[rel]; ok {
			t.Logf("KNOWN (fixed by %s): %s runs the package manager without the shared lock: %v", who, rel, at)
			continue
		}
		t.Errorf("%s runs the package manager without the shared install lock (hostpkg.Lock): %v", rel, at)
	}
}

// takesLock reports whether a file calls hostpkg.Lock (or is hostpkg).
func takesLock(f *ast.File) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := s.X.(*ast.Ident); ok && id.Name == "hostpkg" && s.Sel.Name == "Lock" {
				found = true
			}
		}
		return !found
	})
	return found
}

// The checks themselves, on what they must catch.
func TestTheChecksCatch(t *testing.T) {
	if _, err := exec.Command("sh", "-n", "-c", "if true; then echo; fi").CombinedOutput(); err != nil {
		t.Fatal("sh -n refuses a good script")
	}
	if _, err := exec.Command("sh", "-n", "-c", "if true; then echo").CombinedOutput(); err == nil {
		t.Fatal("sh -n accepts a broken script")
	}
	for s, want := range map[string]string{
		"pgrep -x cloud-hypervisor >/dev/null": "cloud-hypervisor",
		"pkill -TERM -x 'openshell-gateway'":   "openshell-gateway",
		`pgrep -x "kevasod"`:                   "kevasod",
	} {
		m := pgrepRE.FindStringSubmatch(s)
		if m == nil || m[2]+m[3]+m[4] != want {
			t.Errorf("%q: %v", s, m)
		}
	}
	for s, bad := range map[string]bool{
		`pgrep -x cloud-hypervisor`:                                    true,
		`pgrep -x cloud-hyperviso`:                                     false,
		`for p in a b; do pkill -KILL -x "$p"; done`:                   true,
		`for p in a b; do pkill -KILL -x "$(printf %.15s "$p")"; done`: false,
		`pgrep -f cloud-hypervisor-long-command-line`:                  false,
	} {
		if got := pgrepProblem(s) != ""; got != bad {
			t.Errorf("pgrepProblem(%q): %v, want %v", s, got, bad)
		}
	}
	for s, want := range map[string]bool{"DEBIAN_FRONTEND=noninteractive apt-get install -y x": true, "dpkg-query -W x": false,
		"command -v docker": false, "yum install x": true, "(apt-get update)": true, "echo apt-gets": false} {
		if pkgWord(s) != want {
			t.Errorf("pkgWord(%q) = %v", s, !want)
		}
	}
}

// The snippets built at run time, rendered with awkward inputs (quotes, spaces, a user, another
// shell): each still parses, so a silo's own script can't break the wrapper around it.
func TestDynamicSnippetsParse(t *testing.T) {
	awkward := `echo "it's" $HOME; [ -n "$x" ] && printf '%s\n' 'a b'`
	var scripts []string
	for _, user := range []string{"", "root", "app", "o'brien"} {
		for _, shell := range []string{"", "bash"} {
			d := v1.Daemon{Name: "web-1", Run: awkward, User: user, Shell: shell}
			u := v1.Upkeep{Name: "disk", Check: awkward, Fix: awkward, User: user, Shell: shell}
			for _, c := range [][]string{keep.StartCommand(d), keep.ProbeCommand(d), keep.CheckCommand(u), keep.FixCommand(u)} {
				scripts = append(scripts, c[2])
			}
		}
	}
	scripts = append(scripts, keep.StopCommand("web-1")[2])
	scripts = append(scripts, cloudhypervisor.GuestMountScript(cloudhypervisor.Layout{
		Disks:  []cloudhypervisor.VolumeDisk{{Name: "data", MountPath: "/var/lib/data", Serial: "kv-0123456789abcdef"}, {Name: "logs", MountPath: "/var/log/app dir", Serial: "kv-fedcba"}},
		Shares: []cloudhypervisor.Share{{Name: "home", MountPath: "/home/data", Tag: "kv-home"}},
	}))
	for i, s := range scripts {
		if out, err := exec.Command("sh", "-n", "-c", s).CombinedOutput(); err != nil {
			t.Errorf("script %d: sh -n: %v: %s\n%s", i, err, out, s)
		}
		for _, m := range pgrepRE.FindAllStringSubmatch(s, -1) {
			if name := m[2] + m[3] + m[4]; len(name) > 15 {
				t.Errorf("script %d: %s -x %q never matches", i, m[1], name)
			}
		}
	}
	if len(scripts) < 30 {
		t.Fatal(fmt.Sprint(len(scripts), " scripts"))
	}
}
