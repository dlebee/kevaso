package rbac

import (
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func r(res string, verbs ...string) v1.PolicyRule {
	return v1.PolicyRule{Verbs: verbs, Resources: []string{res}}
}

func TestMissing(t *testing.T) {
	for _, c := range []struct {
		name       string
		held, want []v1.PolicyRule
		missing    int
	}{
		{"same", []v1.PolicyRule{r("silos", "get")}, []v1.PolicyRule{r("silos", "get")}, 0},
		{"verbs across rules", []v1.PolicyRule{r("silos", "get"), r("silos", "list")}, []v1.PolicyRule{r("silos", "get", "list")}, 0},
		{"one verb beyond", []v1.PolicyRule{r("silos", "get")}, []v1.PolicyRule{r("silos", "get", "list")}, 1},
		{"star held covers", []v1.PolicyRule{r("*", "*")}, []v1.PolicyRule{r("silos/exec", "create"), r("*", "*"), r("*/status", "update")}, 0},
		{"star wanted needs star", []v1.PolicyRule{r("silos", "get", "list", "create")}, []v1.PolicyRule{r("*", "get")}, 1},
		{"star verb wanted needs star", []v1.PolicyRule{r("silos", "get", "list", "create")}, []v1.PolicyRule{r("silos", "*")}, 1},
		{"sub-resource star", []v1.PolicyRule{r("*/status", "update")}, []v1.PolicyRule{r("silos/status", "update"), r("*/status", "update")}, 0},
		{"subresource isn't the resource", []v1.PolicyRule{r("silos", "get")}, []v1.PolicyRule{r("silos/exec", "get")}, 1},
		{"secrets list covers get", []v1.PolicyRule{r("secrets", "list")}, []v1.PolicyRule{r("secrets", "get", "watch")}, 0},
		{"secrets write covers create", []v1.PolicyRule{r("secrets", v1.VerbWrite)}, []v1.PolicyRule{r("secrets", "create", "delete")}, 0},
		{"secrets use isn't read-value", []v1.PolicyRule{r("secrets", v1.VerbUse)}, []v1.PolicyRule{r("secrets", v1.VerbReadValue)}, 1},
		{"named held, wider wanted", []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"silos"}, ResourceNames: []string{"a"}}}, []v1.PolicyRule{r("silos", "get")}, 1},
		{"named held, same name", []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"silos"}, ResourceNames: []string{"a", "b"}}}, []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"silos"}, ResourceNames: []string{"b"}}}, 0},
		{"selector held, wider wanted", []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"secrets"}, Selector: map[string]string{"t": "x"}}}, []v1.PolicyRule{r("secrets", "get")}, 1},
		{"selector held, narrower wanted", []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"secrets"}, Selector: map[string]string{"t": "x"}}}, []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"secrets"}, Selector: map[string]string{"t": "x", "u": "y"}}}, 0},
		{"selector held, a name wanted", []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"secrets"}, Selector: map[string]string{"t": "x"}}}, []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"secrets"}, ResourceNames: []string{"a"}}}, 1},
		{"nothing held", nil, []v1.PolicyRule{r("silos", "get")}, 1},
		{"nothing wanted", nil, nil, 0},
	} {
		if got := Missing(c.held, c.want); len(got) != c.missing {
			t.Errorf("%s: missing %v, want %d", c.name, got, c.missing)
		}
	}
}
