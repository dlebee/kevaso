package session

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The example is built on the public modules only: nothing from kevaso.com/core outside api and
// sdk (its own packages aside).
func TestOnlyPublicModules(t *testing.T) {
	for _, dir := range []string{".", "../cmd/kevaso-operator-session"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range af.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasPrefix(p, "kevaso.com/") && !strings.HasPrefix(p, "kevaso.com/core/api/") &&
					!strings.HasPrefix(p, "kevaso.com/core/sdk/") && !strings.HasPrefix(p, "kevaso.com/core/examples/operator-session/") {
					t.Errorf("%s imports %s: the example uses kevaso.com/core/api and kevaso.com/core/sdk only", f, p)
				}
			}
		}
	}
}
