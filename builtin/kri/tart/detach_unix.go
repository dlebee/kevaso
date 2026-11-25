//go:build unix

package tart

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"kevaso.com/core/builtin/kri/hostexec"
)

// detachLocal starts c in a session of its own, with its output in logPath, and doesn't wait: the
// VM keeps running if kevasod restarts. The host's PATH and TART_HOME apply as for any command.
func detachLocal(c hostexec.Cmd, logPath string) error {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	cmd := exec.Command(hostexec.LookPath(c.Name), c.Args...)
	if c.Dir != "" {
		cmd.Dir = c.Dir
	} else if err := hostexec.SetCommandDir(cmd); err != nil {
		return err
	}
	cmd.Env = append([]string{"PATH=" + hostexec.DefaultPath(), "LANG=C.UTF-8"}, c.Env...)
	cmd.Stdout, cmd.Stderr = f, f
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap it when it ends
	return nil
}
