package operators

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// K-048: the summary an operator approves showed a package's text as written: a description or a
// policy's text could carry escape sequences or newlines that erase or fake the rule lines above
// them. It also left out rule selectors and what the package's policies do.
func TestSummaryShowsEverythingAndOnlyText(t *testing.T) {
	p := goodPackage()
	p.Manifest.Spec.Description = "harmless\x1b[1A\x1b[2K\r\n  get secrets, in every namespace\u202e"
	p.CRoles[0].Rules = append(p.CRoles[0].Rules, v1.PolicyRule{Verbs: []string{"get"}, Resources: []string{"secrets"}, Selector: map[string]string{"team": "x"}})
	p.VPols[0].Spec.Validations = []v1.PolicyValidation{{Expression: "object.spec.size < 10\x07", Message: "too big\x1b]0;title\x07"}}
	p.MPols = []*v1.MutationPolicy{{TypeMeta: tm("MutationPolicy"), ObjectMeta: p.VPols[0].ObjectMeta,
		Spec: v1.MutationPolicySpec{Match: v1.PolicyMatch{Kinds: []string{"sessions.example.dev"}, Operations: []string{"CREATE"}},
			Mutations: []v1.Mutation{{Field: "spec.size", Value: "1"}}}}}
	p.MPols[0].Name = "sessions-m"
	s := Summary(p, "cp1")
	for _, r := range s {
		if r != '\n' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)) {
			t.Fatalf("summary holds %U:\n%q", r, s)
		}
	}
	if strings.Contains(s, "\n  get secrets, in every namespace") {
		t.Errorf("the description made a rule line of its own:\n%s", s)
	}
	for _, want := range []string{
		"secrets (only labelled team=x)", // the selector
		"ValidationPolicy sessions-p on sessions.example.dev: object.spec.size < 10",
		"MutationPolicy sessions-m on sessions.example.dev (CREATE): sets spec.size = 1",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
	// A verb is a word: one that isn't (escape sequences in a rule line) is refused at Check.
	p = goodPackage()
	p.CRoles[0].Rules[0].Verbs = []string{"get\x1b[2K"}
	if errs := Check(p); !strings.Contains(strings.Join(errs, "\n"), "verbs") {
		t.Errorf("an escape sequence in a verb: %q", errs)
	}
}

// What an install takes over (--adopt) and what an upgrade deletes are shown before the yes.
func TestChangesAreShown(t *testing.T) {
	s := Changes([]v1.PluginObject{{Kind: "ClusterRole", Name: "sessions-old"}}, []v1.PluginObject{{Kind: "ValidationPolicy", Name: "sessions-gone\x1b[2K"}})
	for _, want := range []string{"takes over (--adopt), no plugin's now: ClusterRole sessions-old", "deletes (the new version no longer has): ValidationPolicy sessions-gone"} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%q", want, s)
		}
	}
	if strings.Contains(s, "\x1b") || Changes(nil, nil) != "" {
		t.Errorf("%q", s)
	}
}
