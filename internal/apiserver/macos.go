package apiserver

import (
	v1 "kevaso.com/core/api/v1"
)

// macSiloProblems are what a macOS silo (runtime tart) can't have yet. Each would be accepted and
// then silently not done: a macOS guest isn't on the cluster's network (no mesh on a Mac, no
// silo address), and the egress gate and its secret delivery are Linux host features. Refusing
// them keeps a grant from looking enforced when it isn't. Pure.
func macSiloProblems(silo *v1.Silo) []string {
	var out []string
	if len(silo.Spec.Ports) > 0 || len(silo.Spec.Services) > 0 {
		out = append(out, "tart: a macOS silo has no cluster address yet (a Mac isn't on the mesh), so it can't declare ports or a service; reach it with kvo exec, kvo ssh and kvo cp")
	}
	if len(silo.Spec.Grants) > 0 {
		out = append(out, "tart: grants (egress rules and secrets) are enforced by the Linux host's egress gate or by OpenShell; a macOS silo has neither, so it can't use any yet")
	}
	return out
}
