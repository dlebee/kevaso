package kri

import "errors"

// TTY is the terminal an Exec runs on (`kvo exec -t`, `kvo ssh`, `kvo ui`).
type TTY struct {
	Size WindowSize
	// Resize carries the client's new window sizes; it is closed when the client is done.
	Resize <-chan WindowSize
}

// WindowSize is a terminal's size in characters.
type WindowSize struct {
	Rows, Cols uint16
}

// ErrNoTTY: the runtime can't run a command on a terminal.
var ErrNoTTY = errors.New("this runtime can't run commands on a terminal")

// ExecMarkerEnv is set, with a value unique to one Exec, in the environment of the command a
// runtime starts in a silo, so the runtime can find and stop everything that command started when
// its client goes away (the runtime's own client, docker exec or ssh, doesn't do that). The
// built-in runtimes don't rely on it alone: a command may clear its environment, so they also
// sweep the exec's process tree and session (builtin/kri/hostexec).
const ExecMarkerEnv = "KEVASO_EXEC"
