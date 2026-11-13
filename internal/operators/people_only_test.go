package operators

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// approve is people's (design §8.7, §7.2d): a plugin's controller is a service account, which can
// never answer, so a plugin role asking for approve anywhere, or for a secret's value, is refused
// at install rather than granted and silently useless.
func TestPluginRolesNeverHoldPeoplesVerbs(t *testing.T) {
	for _, c := range []struct {
		verb, res string
	}{
		{v1.VerbApprove, "secrets"},
		{v1.VerbReadValue, "secrets"},
		{v1.VerbApprove, v1.ResourceExposure},
	} {
		errs := RuleProblems(v1.PolicyRule{Verbs: []string{"get", c.verb}, Resources: []string{c.res}})
		if !strings.Contains(strings.Join(errs, "; "), c.verb+" on "+c.res+" is for people") {
			t.Errorf("a plugin role with %s on %s: %v", c.verb, c.res, errs)
		}
	}
	if errs := RuleProblems(v1.PolicyRule{Verbs: []string{v1.VerbOpen}, Resources: []string{v1.ResourceExposure}}); len(errs) != 0 {
		t.Errorf("open on silos/exposure (a controller opening its silos' leases): %v", errs)
	}
}
