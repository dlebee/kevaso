package hostreset

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// StillRunningScript, run with stand-ins for systemctl and pgrep: only units that are inactive or
// failed with no main process, and no kevasod process, print nothing (review claim 4).
func TestStillRunningScriptSaysWhatRuns(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	cases := []struct {
		name, active, pid, procs string
		want                     []string // substrings; none: prints nothing
	}{
		{"stopped", "inactive", "0", "", nil},
		{"failed, nothing left", "failed", "0", "", nil},
		{"deactivating", "deactivating", "4242", "", []string{"unit kevasod.service is deactivating", "main process 4242"}},
		{"activating", "activating", "0", "", []string{"is activating"}},
		{"failed with its main process", "failed", "4242", "", []string{"main process 4242"}},
		{"a kevasod process systemd lost", "inactive", "0", "4243 /usr/local/bin/kevasod", []string{"process 4243 /usr/local/bin/kevasod"}},
		{"systemctl doesn't answer", "", "", "", []string{"systemd doesn't say"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			stub := func(name, body string) {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!"+sh+"\n"+body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			active := `echo ` + tc.active + `; [ ` + tc.active + `x = activex ]`
			if tc.active == "" {
				active = `exit 1`
			}
			stub("systemctl", `case "$1" in is-active) `+active+`;; show) [ -n "`+tc.pid+`" ] && echo `+tc.pid+`;; esac`)
			stub("pgrep", `[ -n "`+tc.procs+`" ] && echo "`+tc.procs+`"; exit 0`)
			stub("sed", `exec /usr/bin/sed "$@"`)
			cmd := exec.Command(sh, "-c", StillRunningScript)
			cmd.Env = []string{"PATH=" + bin}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			got := strings.TrimSpace(string(out))
			if len(tc.want) == 0 && got != "" {
				t.Fatalf("printed %q: nothing runs", got)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Fatalf("printed %q, want %q", got, w)
				}
			}
		})
	}
}
