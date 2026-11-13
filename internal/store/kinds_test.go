package store_test

import (
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// The store holds API objects under their kind and the control plane's own records (join tokens,
// pane bundles, the leader's lease, sealed secret values, issuer records, …) under kinds of their
// own, side by side. An internal kind that is also an API kind's would be listed, watched and
// decoded as API objects (the leader's lease once shared "Lease" with port leases). A defined
// kind is stored under PLURAL.GROUP, which has a dot.
//
// So, in every store.Key and store.Selector the code writes: an API kind is written as itself (a
// literal, "Silo"), and must be one; a kind of the control plane's own is a named constant, and
// must have no dot and match no built-in kind's name, plural or short name, without regard to
// case. A built-in kind added later under such a name fails here too.
func TestInternalStoreKindsAreNotAPIKinds(t *testing.T) {
	literals, consts, dynamic := storeKinds(t, "../..", "internal", "builtin", "cmd")
	for k, where := range literals {
		if b, ok := v1.Lookup(k); !ok || b.Kind != k {
			t.Errorf("store kind %q (%s) is written as a literal but isn't an API kind: name it with a constant", k, where[0])
		}
	}
	for _, want := range []string{"JoinToken", "LeaderLease", "PaneBundle", "SecretValue", "OIDCSession"} {
		if consts[want] == nil {
			t.Errorf("didn't find the store kind %s: the scan is missing something (found %v)", want, keys(consts))
		}
	}
	for k, where := range consts {
		if strings.Contains(k, ".") {
			t.Errorf("store kind %q (%s) has a dot: it could be a defined kind's PLURAL.GROUP", k, where[0])
		}
		for _, b := range v1.Kinds() {
			for _, n := range append([]string{b.Kind, b.Plural}, b.ShortNames...) {
				if strings.EqualFold(n, k) {
					t.Errorf("store kind %q (%s) is the built-in kind %s's name %q: rename one of them", k, where[0], b.Kind, n)
				}
			}
		}
	}
	// What the scan couldn't resolve must be the API's own kinds, taken from the request or an
	// object: anything else would be a store kind this test can't see.
	allowed := map[string]bool{
		"t.kind.Kind":       true, // apiserver: the request's kind, looked up in the API's
		"d.Spec.Resource()": true, // apiserver: a KindDefinition's PLURAL.GROUP
		"kind":              true, // apiserver/moves.go: Silo or SiloSet
		"k":                 true, // rbac: the role and binding kinds
		"sel.Kind":          true, // the store itself, echoing a caller's selector
		"parts[0]":          true, // the etcd store parsing its own keys
	}
	for expr, where := range dynamic {
		if !allowed[expr] {
			t.Errorf("a store kind from %s (%s): make it a constant this test can read, or say here why it's an API kind", expr, where[0])
		}
	}
}

func keys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// storeKinds finds the Kind of every store.Key and store.Selector literal in the non-test Go files
// under dirs (but the store's own test helpers): written as a string, as a constant (of the same
// package or another of this module's), or what it couldn't resolve.
func storeKinds(t *testing.T, root string, dirs ...string) (literals, consts, dynamic map[string][]string) {
	t.Helper()
	fset := token.NewFileSet()
	type pkg struct {
		files  []*ast.File
		consts map[string]string
	}
	pkgs := map[string]*pkg{} // by directory, relative to root
	for _, d := range dirs {
		err := filepath.WalkDir(filepath.Join(root, d), func(p string, e os.DirEntry, err error) error {
			if err == nil && e.IsDir() && e.Name() == "storetest" {
				return filepath.SkipDir
			}
			if err != nil || e.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, filepath.Dir(p))
			if pkgs[rel] == nil {
				pkgs[rel] = &pkg{consts: map[string]string{}}
			}
			pk := pkgs[rel]
			pk.files = append(pk.files, f)
			for _, decl := range f.Decls {
				g, ok := decl.(*ast.GenDecl)
				if !ok || g.Tok != token.CONST {
					continue
				}
				for _, s := range g.Specs {
					vs := s.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if i < len(vs.Values) {
							if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
								pk.consts[n.Name], _ = strconv.Unquote(lit.Value)
							}
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	literals, consts, dynamic = map[string][]string{}, map[string][]string{}, map[string][]string{}
	for dir, pk := range pkgs {
		inStore := dir == filepath.Join("internal", "store")
		for _, f := range pk.files {
			imports := map[string]string{} // local name → directory in this module
			for _, im := range f.Imports {
				path, _ := strconv.Unquote(im.Path.Value)
				rel, ok := strings.CutPrefix(path, "kevaso.com/core/")
				if !ok {
					continue
				}
				name := filepath.Base(rel)
				if im.Name != nil {
					name = im.Name.Name
				}
				imports[name] = rel
			}
			isStoreType := func(e ast.Expr) bool {
				switch x := e.(type) {
				case *ast.SelectorExpr:
					id, ok := x.X.(*ast.Ident)
					return ok && imports[id.Name] == "internal/store" && (x.Sel.Name == "Key" || x.Sel.Name == "Selector")
				case *ast.Ident:
					return inStore && (x.Name == "Key" || x.Name == "Selector")
				}
				return false
			}
			ast.Inspect(f, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok || !isStoreType(cl.Type) {
					return true
				}
				for _, el := range cl.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Kind" {
						continue
					}
					at := fset.Position(kv.Pos()).String()
					switch v := kv.Value.(type) {
					case *ast.BasicLit:
						s, _ := strconv.Unquote(v.Value)
						literals[s] = append(literals[s], at)
						continue
					case *ast.Ident:
						if s, ok := pk.consts[v.Name]; ok {
							consts[s] = append(consts[s], at)
							continue
						}
					case *ast.SelectorExpr:
						if id, ok := v.X.(*ast.Ident); ok {
							if other, ok := pkgs[imports[id.Name]]; ok {
								if s, ok := other.consts[v.Sel.Name]; ok {
									consts[s] = append(consts[s], at)
									continue
								}
							}
						}
					}
					e := exprString(fset, kv.Value)
					dynamic[e] = append(dynamic[e], at)
				}
				return true
			})
		}
	}
	return literals, consts, dynamic
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var b strings.Builder
	_ = printNode(&b, fset, e)
	return b.String()
}

func printNode(b *strings.Builder, fset *token.FileSet, e ast.Expr) error {
	return format.Node(b, fset, e)
}
