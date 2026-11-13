package v1

import "time"

// Probes (design §0.6): what "started", "ready" and "alive" mean for a silo beyond its machine
// running. All optional: a silo with none is started and Ready as soon as it runs, and Kevaso
// ensures nothing else about what runs inside.

// Probes are a silo's up to three probes.
type Probes struct {
	// Startup: the silo has come up. Until it passes, readiness and liveness don't run. Its
	// timeout is the overall deadline: past it the silo is StartFailed, and stays up for debugging.
	Startup *Probe `json:"startup,omitempty"`
	// Readiness: it can take work right now. Until it passes the silo isn't Ready.
	Readiness *Probe `json:"readiness,omitempty"`
	// Liveness: it is still healthy. Failing marks it Degraded; onFailure: restart also restarts
	// it, and only then.
	Liveness *Probe `json:"liveness,omitempty"`
}

// Probe is one probe: exactly one of Exec, TCP and HTTP, how often, and how many results in a
// row change its answer.
type Probe struct {
	Exec *ExecProbe `json:"exec,omitempty"`
	TCP  *TCPProbe  `json:"tcp,omitempty"`
	HTTP *HTTPProbe `json:"http,omitempty"`
	// Period: how often it runs (default 10s).
	Period string `json:"period,omitempty"`
	// Timeout: each run's limit (default 5s). On startup it's the overall deadline instead
	// (default 5m), and each run gets the default limit (or the period, if shorter).
	Timeout string `json:"timeout,omitempty"`
	// Successes in a row that make it pass (default 1); Failures in a row that make it fail
	// (default 3). Startup fails only by its deadline, so Failures doesn't apply to it.
	Successes int `json:"successes,omitempty"`
	Failures  int `json:"failures,omitempty"`
	// OnFailure is for liveness only: report (default: Degraded, nothing else) or restart.
	OnFailure string `json:"onFailure,omitempty"`
}

// ExecProbe runs a command inside the silo (through the runtime's exec): exit 0 passes.
type ExecProbe struct {
	Command []string `json:"command"` // argv, run directly (use sh -c for a script)
}

// TCPProbe passes when the port accepts a connection, dialled from the silo's host.
type TCPProbe struct {
	Port string `json:"port"` // the name of one of the silo's declared ports (spec.ports)
}

// HTTPProbe passes when a GET answers 2xx or 3xx, sent from the silo's host.
type HTTPProbe struct {
	Port string `json:"port"`           // a declared port's name
	Path string `json:"path,omitempty"` // default /
}

// Probe names, as status.probes and conditions use them.
const (
	ProbeStartup   = "startup"
	ProbeReadiness = "readiness"
	ProbeLiveness  = "liveness"
)

// Liveness onFailure values.
const (
	OnFailureReport  = "report"
	OnFailureRestart = "restart"
)

// Probe states.
const (
	ProbePending  = "Pending"  // not passed yet (or not running yet: startup gates it)
	ProbePassing  = "Passing"  // passed Successes times in a row and hasn't failed since
	ProbeFailing  = "Failing"  // failed Failures times in a row (startup: past its deadline)
	ProbeCantRun  = "CantRun"  // couldn't run at all: never counted as failed
	ProbeDisabled = "Disabled" // waits for startup to pass
)

// Results of one run.
const (
	ResultSuccess = "Success"
	ResultFailure = "Failure"
	ResultCantRun = "CantRun"
)

// Routing modes (design §0.6): a service says whether its traffic waits for readiness.
const (
	RouteWhenReady   = "ready"   // only while the readiness probe passes
	RouteWhenRunning = "running" // as soon as the silo runs, whatever its probes say
)

// ProbeStatus is how one probe is doing.
type ProbeStatus struct {
	Name      string     `json:"name"`  // startup | readiness | liveness
	State     string     `json:"state"` // Pending | Passing | Failing | CantRun | Disabled
	Since     *time.Time `json:"since,omitempty"`
	Successes int        `json:"successes,omitempty"` // in a row, now
	Failures  int        `json:"failures,omitempty"`  // in a row, now
	// LastResult and LastTime: its last run; Reason: a short why (the end of the output, the
	// HTTP status, the dial error).
	LastResult string     `json:"lastResult,omitempty"`
	LastTime   *time.Time `json:"lastTime,omitempty"`
	Reason     string     `json:"reason,omitempty"`
}

// LivenessRestarts is what liveness onFailure: restart has done to a silo.
type LivenessRestarts struct {
	Count int        `json:"count"`          // restarts since the silo was created
	Last  *time.Time `json:"last,omitempty"` // the last one
	// Backoff is how many restarts in a row came without the silo staying alive in between:
	// the wait before the next grows with it.
	Backoff int `json:"backoff,omitempty"`
}

// Routing is whether a silo's own service gets traffic now, and why (design §0.6).
type Routing struct {
	RouteWhen string     `json:"routeWhen"` // ready | running: as stated, or running without a readiness probe
	Stated    bool       `json:"stated"`    // false: running because there's no readiness probe
	Routed    bool       `json:"routed"`
	Reason    string     `json:"reason,omitempty"` // why it's held
	Since     *time.Time `json:"since,omitempty"`  // held since
}

// FindProbe is the status of the probe called name (nil: none).
func FindProbe(list []ProbeStatus, name string) *ProbeStatus {
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	return nil
}

// HasReadiness reports whether the spec has a readiness probe.
func (s SiloSpec) HasReadiness() bool { return s.Probes != nil && s.Probes.Readiness != nil }
