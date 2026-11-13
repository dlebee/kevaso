package kvo

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/kvoplugin"
)

// Every command Run dispatches is in builtinCommands, so a plugin can never take its name. A new
// command added to Run without adding it there fails here.
func TestBuiltinsCoverRun(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "kvo.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Run" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			if idx, ok := sw.Tag.(*ast.IndexExpr); !ok || types(idx) != "args[0]" {
				return true
			}
			for _, st := range sw.Body.List {
				for _, e := range st.(*ast.CaseClause).List {
					lit, ok := e.(*ast.BasicLit)
					if !ok {
						continue
					}
					name, _ := strconv.Unquote(lit.Value)
					found++
					if !Builtin(name) {
						t.Errorf("kvo %s is a command but not in builtinCommands (plugins.go): a plugin could shadow it", name)
					}
				}
			}
			return true
		})
		return false
	})
	if found < 20 {
		t.Fatalf("found only %d commands in Run: has it changed shape?", found)
	}
}

func types(idx *ast.IndexExpr) string {
	id, ok1 := idx.X.(*ast.Ident)
	lit, ok2 := idx.Index.(*ast.BasicLit)
	if !ok1 || !ok2 {
		return ""
	}
	return id.Name + "[" + lit.Value + "]"
}

// fakePlugin installs a script as a plugin by hand (as if a plugin named NAME had been planted).
func fakePlugin(t *testing.T, root, name, script string) {
	t.Helper()
	dir := filepath.Join(root, "installed", "kevaso", name)
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "files", "kvo-"+name), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	m, _ := json.Marshal(kvoplugin.Manifest{Name: name, Index: "kevaso", Version: "v1.0.0", Entry: "kvo-" + name, Kind: kvoplugin.KindBinary})
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), m, 0o644); err != nil {
		t.Fatal(err)
	}
}

func usePlugins(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	saved := newPluginManager
	newPluginManager = func() (*kvoplugin.Manager, error) {
		return &kvoplugin.Manager{Root: root, Platform: kvoplugin.Host(), Reserved: Builtin}, nil
	}
	t.Cleanup(func() { newPluginManager = saved })
	t.Setenv("KVO_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	t.Setenv("KVO_TOKEN", "")
	return root
}

func TestBuiltinWinsOverAPlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script plugins")
	}
	root := usePlugins(t)
	marker := filepath.Join(t.TempDir(), "ran")
	fakePlugin(t, root, "get", "touch "+marker+"\n")
	fakePlugin(t, root, "hello", "echo \"hello $1 from $KVO_PLUGIN_NAME at $KVO_PLUGIN_SERVER\"\necho oops >&2\nexit 7\n")
	t.Setenv("KVO_SERVER", "http://127.0.0.1:1") // nothing listens: the built-in get fails
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"get", "silos"}, strings.NewReader(""), &out, &errs); code == 0 {
		t.Fatalf("get against nothing succeeded: %s", out.String())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the plugin named get ran instead of kvo get")
	}
	out.Reset()
	errs.Reset()
	code := Run(context.Background(), []string{"hello", "world"}, strings.NewReader(""), &out, &errs)
	if code != 7 || out.String() != "hello world from hello at http://127.0.0.1:1\n" || errs.String() != "oops\n" {
		t.Fatalf("plugin: exit %d, %q %q", code, out.String(), errs.String())
	}
	// Not installed and not a command: as before.
	errs.Reset()
	if code := Run(context.Background(), []string{"nope"}, strings.NewReader(""), &out, &errs); code != 1 || !strings.Contains(errs.String(), `unknown command "nope"`) {
		t.Fatalf("unknown: %d %s", code, errs.String())
	}
}

func TestPluginTokenRefusesClientCertificates(t *testing.T) {
	usePlugins(t)
	cfg := os.Getenv("KVO_CONFIG")
	if err := kvoconfig.AddContext(cfg, "admin", "https://127.0.0.1:1", []byte("ca"), []byte("cert"), []byte("key")); err != nil {
		t.Fatal(err)
	}
	t.Setenv(kvoplugin.EnvContext, "admin")
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"plugin", "token"}, strings.NewReader(""), &out, &errs); code != 1 || !strings.Contains(errs.String(), "never hands to a plugin") {
		t.Fatalf("cert context: %d %q %q", code, out.String(), errs.String())
	}
	// A dev server: no token, and that's fine.
	t.Setenv(kvoplugin.EnvContext, "")
	out.Reset()
	if code := Run(context.Background(), []string{"plugin", "token"}, strings.NewReader(""), &out, &errs); code != 0 || strings.TrimSpace(out.String()) != `{"token":""}` {
		t.Fatalf("dev: %d %q", code, out.String())
	}
}

func TestPluginInstallRefusesBuiltinNames(t *testing.T) {
	usePlugins(t)
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"plugin", "install", "apply"}, strings.NewReader(""), &out, &errs); code != 1 || !strings.Contains(errs.String(), "kvo's own commands") {
		t.Fatalf("install apply: %d %s", code, errs.String())
	}
	if code := Run(context.Background(), []string{"plugin"}, strings.NewReader(""), &out, &errs); code != 2 {
		t.Fatalf("bare plugin: %d", code)
	}
}
