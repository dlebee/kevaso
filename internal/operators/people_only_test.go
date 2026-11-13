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

// K-003: who may sign in and what may join as a host are people's: a plugin role never holds
// invites, jointokens or users, on any subresource.
func TestPluginRolesNeverMintPeople(t *testing.T) {
	for _, res := range []string{"invites", "jointokens", "users", "invites/x", "users/status"} {
		if errs := RuleProblems(v1.PolicyRule{Verbs: []string{"create"}, Resources: []string{res}}); len(errs) == 0 {
			t.Errorf("a plugin role on %q was accepted", res)
		}
	}
}

// K-010: a plugin role names plain resources: nothing with a wildcard in it (it would match the
// forbidden ones), nothing that is not a resource name.
func TestPluginRoleResourcesAreStrict(t *testing.T) {
	for _, res := range []string{
		"*/token", "*/exposure", "*/status", "serviceaccounts/*", "*s", "sil*", "silos*", "?", "silos/ status", "Silos", "",
	} {
		if errs := RuleProblems(v1.PolicyRule{Verbs: []string{"create"}, Resources: []string{res}}); len(errs) == 0 {
			t.Errorf("a plugin role on %q was accepted", res)
		}
	}
}

// Rules the plugins that exist ask for pass (kevaso-provider-linode and -juicefs ship a manifest
// without roles: the rules here are the example operator's roles.yaml, the one plugin role
// the project documents, and what a provider's controller does with the API).
func TestPluginRolesOfTheKnownPluginsPass(t *testing.T) {
	for _, r := range []v1.PolicyRule{
		{Verbs: []string{"get", "list", "watch", "update"}, Resources: []string{"sessions.example.dev"}},
		{Verbs: []string{"update"}, Resources: []string{"sessions.example.dev/status"}},
		{Verbs: []string{"get", "list", "watch", "create", "delete"}, Resources: []string{"silos"}},
		{Verbs: []string{"get", "list", "watch", "update"}, Resources: []string{"hosts", "hosts/status", "ips", "ips/status", "silos/status", "volumes", "classes"}},
	} {
		if errs := RuleProblems(r); len(errs) != 0 {
			t.Errorf("%v on %v: %v", r.Verbs, r.Resources, errs)
		}
	}
}
