package policy

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// K-066 at admission: an OpenShell silo whose grant injects into an env name OpenShell's CLI
// would act on (LD_PRELOAD, HOME, OPENSHELL_*) is refused, saying why.
func TestAnInjectedEnvNameIsChecked(t *testing.T) {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "agent", Namespace: "dev"}, Spec: v1.SiloSpec{Runtime: "openshell", Grants: []string{"api"}}}
	g := &v1.Grant{ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "dev"}, Spec: v1.GrantSpec{Secrets: []v1.GrantSecret{
		{Name: "api-key", Deliver: v1.DeliverInject, Env: "LD_PRELOAD", To: &v1.InjectTarget{Host: "api.example.com"}}}}}
	problems := Check(s, []*v1.Grant{g}, nil)
	if len(problems) == 0 || !strings.Contains(strings.Join(problems, "; "), "LD_PRELOAD") {
		t.Fatalf("problems: %v", problems)
	}
}
