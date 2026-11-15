package agent

// The machine running the tests (CI's are VMs) never changes what a test sees: its agents count
// silence as on bare metal unless a test sets Agent.HostIsVM (K-093).
func init() { detectVM = func() bool { return false } }
