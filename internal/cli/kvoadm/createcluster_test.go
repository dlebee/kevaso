package kvoadm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// K-032, kvoadm's half (host lane). Since brainstorm §0.7, a control plane never creates a cluster
// unless it is asked to explicitly: `kevasod admin create-cluster --cluster NAME --data DIR`
// writes the record <DIR>/pki/cluster.json that makes the next start create it
// (controlplane.CreateCluster). kevasod's unit never carries create mode, so a node whose data is
// lost refuses to start instead of booting an empty cluster.
//
// kvoadm init must run `kevasod admin create-cluster --cluster <o.Cluster> --data /var/lib/kevaso`
// over SSH after bootstrap and before installUnits, on the path without --restore only (a restore
// brings the record from the backup, and `kevasod admin restore` marks it). The test reads
// initCluster's source, because initCluster talks to a real SSH connection.
func TestK032InitCreatesTheClusterExplicitly(t *testing.T) {
	t.Skip("K-032, host lane: kvoadm init must run kevasod admin create-cluster before installUnits (see the comment); remove this skip with that change")
	src, err := os.ReadFile("kvoadm.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "kvoadm.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body string
	ast.Inspect(f, func(n ast.Node) bool {
		if fd, ok := n.(*ast.FuncDecl); ok && fd.Name.Name == "initCluster" {
			body = string(src[fset.Position(fd.Pos()).Offset:fset.Position(fd.End()).Offset])
			return false
		}
		return true
	})
	if body == "" {
		t.Fatal("no initCluster in kvoadm.go")
	}
	create, install := strings.Index(body, "kevasod admin create-cluster"), strings.Index(body, "installUnits(")
	if create < 0 || install < 0 || create > install {
		t.Fatalf("initCluster must run `kevasod admin create-cluster --cluster NAME --data /var/lib/kevaso` before installUnits (create at %d, installUnits at %d)", create, install)
	}
	if !strings.Contains(body[:install], "--cluster") {
		t.Fatal("create-cluster must name the cluster (--cluster o.Cluster)")
	}
}
