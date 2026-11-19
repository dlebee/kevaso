package hostexec

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "kevaso-hostexec-parent-")
	if err != nil {
		panic(err)
	}
	commandParent = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestCommandsRunInAnEmptyDirectory(t *testing.T) {
	var out bytes.Buffer
	code, err := (Local{}).Run(context.Background(), Cmd{Name: "/bin/pwd", Stdout: &out})
	if err != nil || code != 0 {
		t.Fatalf("pwd: %d %v", code, err)
	}
	got := strings.TrimSpace(out.String())
	if !strings.Contains(got, "kevaso-hostexec-") {
		t.Fatalf("command ran in %q", got)
	}
}
