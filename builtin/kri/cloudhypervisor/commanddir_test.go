package cloudhypervisor

import (
	"os"
	"testing"

	"kevaso.com/core/builtin/kri/hostexec"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "kevaso-ch-commands-")
	if err != nil {
		panic(err)
	}
	hostexec.SetCommandParent(dir)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
