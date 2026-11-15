package agent

import (
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/container"
	"kevaso.com/core/builtin/kri/openshell"
)

// The built-in runtimes take the agent's reset gate inside their Reset, right before they remove
// anything (review claim 3): a signature that drifts would silently fall back to the gate before
// Reset.
var (
	_ gatedResetter = (*cloudhypervisor.Runtime)(nil)
	_ gatedResetter = (*container.Runtime)(nil)
	_ gatedResetter = (*openshell.Runtime)(nil)
)
