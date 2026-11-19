package hostexec

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resolved(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHostCommandsLiveUnderTheRuntimeDirectory(t *testing.T) {
	if defaultCommandParent != "/run/kevaso" {
		t.Fatalf("host commands run under %s", defaultCommandParent)
	}
	var out bytes.Buffer
	code, err := (Local{}).Run(context.Background(), Cmd{Name: "/bin/pwd", Stdout: &out})
	if err != nil || code != 0 {
		t.Fatalf("pwd: %d %v", code, err)
	}
	got := resolved(t, strings.TrimSpace(out.String()))
	parent := resolved(t, commandParent)
	if !strings.HasPrefix(got, parent+string(os.PathSeparator)) || !strings.Contains(got, "kevaso-hostexec-") {
		t.Fatalf("command ran in %q, want a directory under %s", got, parent)
	}
}

func TestTheCommandDirectoryIsMadeAgainWhenItIsGone(t *testing.T) {
	var out bytes.Buffer
	code, err := (Local{}).Run(context.Background(), Cmd{Name: "/bin/pwd", Stdout: &out})
	if err != nil || code != 0 {
		t.Fatalf("pwd: %d %v", code, err)
	}
	first := strings.TrimSpace(out.String())
	if err := os.RemoveAll(first); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	code, err = (Local{}).Run(context.Background(), Cmd{Name: "/bin/pwd", Stdout: &out})
	if err != nil || code != 0 {
		t.Fatalf("after the directory was removed, pwd: %d %v", code, err)
	}
	secondRaw := strings.TrimSpace(out.String())
	second := resolved(t, secondRaw)
	parent := resolved(t, commandParent)
	if secondRaw == first || !strings.HasPrefix(second, parent+string(os.PathSeparator)) {
		t.Fatalf("command ran in %q after %q was removed", second, first)
	}
}
