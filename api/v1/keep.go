package v1

import "time"

// Daemons and upkeep (design §0.5): after init, two lists keep the inside of a silo in its desired
// state. The host's agent runs both through the runtime's exec, so nothing of Kevaso's is put into
// the silo.

// Daemon is a long-running process inside the silo, restarted if it dies.
type Daemon struct {
	Name    string `json:"name"`              // lower-case letters, digits and -
	Run     string `json:"run"`               // a script, run by Shell
	Shell   string `json:"shell,omitempty"`   // default sh
	User    string `json:"user,omitempty"`    // default root
	Restart string `json:"restart,omitempty"` // always (default) | onFailure | never
}

// Restart policies.
const (
	RestartAlways    = "always"
	RestartOnFailure = "onFailure"
	RestartNever     = "never"
)

// Upkeep is a check, and a fix run only when the check fails.
type Upkeep struct {
	Name  string `json:"name"`
	Every string `json:"every"` // how often the check runs, e.g. 6h
	Check string `json:"check"` // exit 0: fine
	Fix   string `json:"fix"`   // run when the check fails; the check runs again after
	Shell string `json:"shell,omitempty"`
	User  string `json:"user,omitempty"`
}

// Daemon states.
const (
	DaemonRunning = "Running"
	DaemonWaiting = "Waiting" // dead, restarting after a backoff
	DaemonExited  = "Exited"  // dead, not restarted (its restart policy)
)

// DaemonStatus is one daemon's state.
type DaemonStatus struct {
	Name      string     `json:"name"`
	State     string     `json:"state"`
	Restarts  int        `json:"restarts,omitempty"`
	StartedAt *time.Time `json:"startedAt,omitempty"`
	ExitCode  *int       `json:"exitCode,omitempty"` // how it last ended
	NextStart *time.Time `json:"nextStart,omitempty"`
}

// Upkeep states.
const (
	UpkeepOK     = "OK"     // the check passed
	UpkeepFixed  = "Fixed"  // the check failed, the fix ran, the check passes now
	UpkeepFailed = "Failed" // the fix didn't help: the silo is Degraded
)

// UpkeepStatus is how one upkeep task last went.
type UpkeepStatus struct {
	Name      string     `json:"name"`
	State     string     `json:"state"`
	LastCheck *time.Time `json:"lastCheck,omitempty"`
	LastFix   *time.Time `json:"lastFix,omitempty"`
	Message   string     `json:"message,omitempty"` // the end of the output when something failed
}
