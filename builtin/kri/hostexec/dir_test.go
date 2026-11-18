package hostexec

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

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
