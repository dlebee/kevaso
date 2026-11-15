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
		otherNS                  bool     // the kevasod process is in another mount namespace (a silo's)
		want                     []string // substrings; none: prints nothing
	}{
		{"stopped", "inactive", "0", "", false, nil},
		{"failed, nothing left", "failed", "0", "", false, nil},
		{"deactivating", "deactivating", "4242", "", false, []string{"unit kevasod.service is deactivating", "main process 4242"}},
		{"activating", "activating", "0", "", false, []string{"is activating"}},
		{"failed with its main process", "failed", "4242", "", false, []string{"main process 4242"}},
		{"a kevasod process systemd lost", "inactive", "0", "4243 /usr/local/bin/kevasod", false, []string{"process 4243 /usr/local/bin/kevasod"}},
		{"systemctl doesn't answer", "", "", "", false, []string{"systemd doesn't say"}},
		// K-114: Kevaso run inside a container silo is no kevasod of this host's.
		{"a silo's kevasod", "inactive", "0", "4244 /usr/local/bin/kevasod", true, nil},
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
			other := "mnt:[4026531841]"
			if !tc.otherNS {
				other = "mnt:[4026531840]"
			}
			stub("readlink", `case "$1" in /proc/1/ns/mnt) echo "mnt:[4026531840]";; *) echo "`+other+`";; esac`)
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
