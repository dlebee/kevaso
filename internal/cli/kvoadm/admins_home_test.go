package kvoadm

import (
	"os/exec"
	"os/user"
	"runtime"
	"testing"
)

// The admin-key sync finds the login user's home on Linux (getent) and on a Mac (dscl: no getent).
func TestAuthorizedKeysReadFindsTheHomeHere(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Linux and macOS hosts only")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if err := exec.Command("sh", "-c", AuthorizedKeysRead(u.Username)).Run(); err != nil {
		t.Fatalf("reading %s's authorized_keys on %s: %v (the home folder wasn't found)", u.Username, runtime.GOOS, err)
	}
	if err := exec.Command("sh", "-c", homeOf(u.Username)+`[ "$h" = "`+u.HomeDir+`" ]`).Run(); err != nil {
		t.Fatalf("homeOf(%s) isn't %s", u.Username, u.HomeDir)
	}
}
