package worker

import "testing"

// T-13 (K-079): the worker hands the agent's local endpoint the loaded rules' bindings
// (agent.Agent.Bound = bindings.Port) and the network loop the same *Bindings
// (NetworkOptions.Bindings). Each half has a test (TestTheLoadedRulesBindingsReach… in this
// package covers the loop; the agent's own tests cover Bound), but nothing runs Run as kevasod
// does and asks the agent it built whether Bound is set: removing `Bound: bindings.Port` from
// Run, or `Bindings: bindings` from its RunNetworkWith call, leaves every package green.
//
// The seam this needs, in product code (host lane): Config.OnAgent func(*agent.Agent), called
// in Run right after the agent is built, so a test can assert a.Bound != nil and that
// a.Bound(addr) answers once applyRules has been called for a silo placed on the host.
// The test is then: Run with a fake bridge runtime and applyRules stubbed (as
// laststate_test.go does), wait for the rules, then require OnAgent's agent to bind the silo's
// address to its tap.
func TestRunConnectsTheAgentsEndpointToTheLoadedBindings(t *testing.T) {
	t.Skip("needs Config.OnAgent (or another way to reach the agent Run builds): see the comment; mutations G-180 and G-181 in hack/mutate survive until then")
}
