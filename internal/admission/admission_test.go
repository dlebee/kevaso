package admission

import (
	"encoding/json"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func vp(name string, match v1.PolicyMatch, vals ...v1.PolicyValidation) *v1.ValidationPolicy {
	return &v1.ValidationPolicy{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: v1.ValidationPolicySpec{Match: match, Validations: vals}}
}

func mp(name string, match v1.PolicyMatch, muts ...v1.Mutation) *v1.MutationPolicy {
	return &v1.MutationPolicy{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: v1.MutationPolicySpec{Match: match, Mutations: muts}}
}

func silo(ns, runtime string) map[string]any {
	return map[string]any{"apiVersion": "kevaso/v1", "kind": "Silo", "metadata": map[string]any{"name": "s", "namespace": ns},
		"spec": map[string]any{"runtime": runtime}}
}

func siloReq(ns, op string) Request {
	return Request{Operation: op, User: "ada", Groups: []string{"devs"}, Verb: strings.ToLower(op), Namespace: ns, Name: "s", Kind: "Silo", Resource: "silos", BuiltIn: true}
}

// The design's example (§4.2): silos in untrusted may not use cloud-hypervisor.
var untrusted = vp("untrusted-runtime", v1.PolicyMatch{Kinds: []string{"Silo"}, Namespaces: []string{"untrusted"}},
	v1.PolicyValidation{Expression: "object.spec.runtime != 'cloud-hypervisor'", Message: "silos in untrusted may not use cloud-hypervisor"})

func TestValidate(t *testing.T) {
	onlyAda := vp("a-only-ada-deletes-labels", v1.PolicyMatch{Kinds: []string{"silos"}, Operations: []string{"UPDATE"}},
		v1.PolicyValidation{Expression: "request.user == 'ada' || oldObject.metadata.labels == object.metadata.labels", Message: "only ada changes labels"})
	defined := vp("db-size", v1.PolicyMatch{Kinds: []string{"databases.acme.dev"}},
		v1.PolicyValidation{Expression: "object.spec.size != '1Ti'", Message: "too big"},
		v1.PolicyValidation{Expression: "'devs' in request.groups", Message: "devs only"})
	everything := vp("z-named", v1.PolicyMatch{Kinds: []string{"*"}},
		v1.PolicyValidation{Expression: "object.metadata.name != 'forbidden'", Message: "that name is taken"})
	set := Compile([]*v1.ValidationPolicy{everything, untrusted, defined, onlyAda}, nil)

	db := map[string]any{"apiVersion": "acme.dev/v1", "kind": "Database", "metadata": map[string]any{"name": "forbidden", "namespace": "x"}, "spec": map[string]any{"size": "1Ti"}}
	dbReq := Request{Operation: "CREATE", User: "bob", Groups: []string{"ops"}, Verb: "create", Namespace: "x", Name: "forbidden", Kind: "Database", Resource: "databases.acme.dev"}
	for _, tc := range []struct {
		name     string
		req      Request
		obj, old map[string]any
		want     []string
	}{
		{"allowed", siloReq("untrusted", "CREATE"), silo("untrusted", "docker"), nil, nil},
		{"refused", siloReq("untrusted", "CREATE"), silo("untrusted", "cloud-hypervisor"), nil, []string{"ValidationPolicy untrusted-runtime: silos in untrusted may not use cloud-hypervisor"}},
		{"other namespace", siloReq("trusted", "CREATE"), silo("trusted", "cloud-hypervisor"), nil, nil},
		{"by plural, on update only", siloReq("x", "UPDATE"), silo("x", "docker"), silo("x", "docker"), nil},
		// Every failure of every matching policy, policies by name: db-size before z-named.
		{"defined kind, all failures in order", dbReq, db, nil, []string{"ValidationPolicy db-size: too big", "ValidationPolicy db-size: devs only", "ValidationPolicy z-named: that name is taken"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := set.Validate(tc.req, tc.obj, tc.old)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
	// A defined kind named like a built-in's Kind doesn't match by Kind: only PLURAL.GROUP names it.
	fake := Request{Operation: "CREATE", Kind: "Silo", Resource: "silos.acme.dev", Namespace: "untrusted"}
	if got := set.Validate(fake, silo("untrusted", "cloud-hypervisor"), nil); len(got) != 0 {
		t.Errorf("a policy on Silo matched silos.acme.dev: %q", got)
	}
}

func TestExempt(t *testing.T) {
	all := vp("no", v1.PolicyMatch{Kinds: []string{"*"}}, v1.PolicyValidation{Expression: "false", Message: "no"})
	set := Compile([]*v1.ValidationPolicy{all}, nil)
	for _, k := range Exempt {
		r := Request{Operation: "CREATE", Kind: k, Resource: strings.ToLower(k) + "s", BuiltIn: true}
		if set.Applies(r) {
			t.Errorf("a policy applies to %s", k)
		}
	}
	if !set.Applies(siloReq("x", "CREATE")) {
		t.Error("* doesn't match silos")
	}
	for _, k := range []string{"ClusterRole", "rolebindings", "ValidationPolicy", "mutationpolicies"} {
		if err := CheckValidationPolicy(vp("p", v1.PolicyMatch{Kinds: []string{k}}, v1.PolicyValidation{Expression: "true"})); err == nil {
			t.Errorf("a policy naming %s was accepted", k)
		}
	}
}

func TestMutate(t *testing.T) {
	// Name order: a-runtime sets the runtime, b-label sees it.
	runtime := mp("a-runtime", v1.PolicyMatch{Kinds: []string{"Silo"}},
		v1.Mutation{Field: "spec.runtime", Value: "'docker'", When: "!has(object.spec.runtime) || object.spec.runtime == ''"},
		v1.Mutation{Field: "spec.resources.cpu", Value: "2"})
	label := mp("b-label", v1.PolicyMatch{Kinds: []string{"Silo"}},
		v1.Mutation{Field: "metadata.labels.kevaso.com/runtime", Value: "object.spec.runtime"},
		v1.Mutation{Field: "metadata.annotations.who", Value: "request.user"},
		v1.Mutation{Field: "spec.drop", Value: "null"})
	for _, order := range [][]*v1.MutationPolicy{{runtime, label}, {label, runtime}} { // list order doesn't matter
		set := Compile(nil, order)
		obj := silo("x", "")
		obj["spec"].(map[string]any)["drop"] = "me"
		changed, err := set.Mutate(siloReq("x", "CREATE"), obj, nil)
		if err != nil || !changed {
			t.Fatalf("mutate: %v, %v", changed, err)
		}
		b, _ := json.Marshal(obj)
		want := `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"annotations":{"who":"ada"},"labels":{"kevaso.com/runtime":"docker"},"name":"s","namespace":"x"},"spec":{"resources":{"cpu":2},"runtime":"docker"}}`
		if string(b) != want {
			t.Errorf("mutated:\n got %s\nwant %s", b, want)
		}
		// Again: nothing changes (mutations are idempotent here), and the when keeps the runtime.
		if changed, err := set.Mutate(siloReq("x", "UPDATE"), obj, obj); err != nil || changed {
			t.Errorf("second pass: %v, %v", changed, err)
		}
	}
}

func TestFailClosed(t *testing.T) {
	broken := vp("broken", v1.PolicyMatch{Kinds: []string{"Silo"}}, v1.PolicyValidation{Expression: "object.spec.nothing.deeper == 1", Message: "x"})
	notBool := vp("not-bool", v1.PolicyMatch{Kinds: []string{"Silo"}}, v1.PolicyValidation{Expression: "'yes'"})
	uncompiled := vp("uncompiled", v1.PolicyMatch{Kinds: []string{"Silo"}}, v1.PolicyValidation{Expression: "object.spec. =="})
	set := Compile([]*v1.ValidationPolicy{uncompiled, notBool, broken}, nil)
	got := strings.Join(set.Validate(siloReq("x", "CREATE"), silo("x", "docker"), nil), "\n")
	for _, w := range []string{"ValidationPolicy broken: validations[0] can't be evaluated", "ValidationPolicy not-bool: validations[0] isn't true or false", "ValidationPolicy uncompiled:", "fail closed"} {
		if !strings.Contains(got, w) {
			t.Errorf("%s\nwant it to say %q", got, w)
		}
	}
	// Policies that don't match aren't consulted, broken or not.
	if got := set.Validate(Request{Operation: "CREATE", Kind: "Host", Resource: "hosts", BuiltIn: true}, map[string]any{}, nil); len(got) != 0 {
		t.Errorf("a broken policy for silos refused a host: %q", got)
	}

	for _, m := range []v1.Mutation{
		{Field: "spec.runtime", Value: "object.spec.nothing.deeper"},   // can't evaluate
		{Field: "spec.runtime.inner", Value: "'x'"},                    // runtime isn't an object
		{Field: "metadata.labels.a", Value: "3"},                       // labels are strings
		{Field: "spec.runtime", Value: "'x'", When: "'not a boolean'"}, // when isn't a boolean
	} {
		set := Compile(nil, []*v1.MutationPolicy{mp("m", v1.PolicyMatch{Kinds: []string{"Silo"}}, m)})
		if _, err := set.Mutate(siloReq("x", "CREATE"), silo("x", "docker"), nil); err == nil || !strings.Contains(err.Error(), "MutationPolicy m:") {
			t.Errorf("%+v: %v, want a refusal naming the policy", m, err)
		}
	}
}

func TestCheckPolicies(t *testing.T) {
	for _, tc := range []struct {
		p    *v1.MutationPolicy
		want string
	}{
		{mp("m", v1.PolicyMatch{}, v1.Mutation{Field: "spec.x", Value: "1"}), "spec.match.kinds"},
		{mp("m", v1.PolicyMatch{Kinds: []string{"Silo"}}), "spec.mutations: at least one"},
		{mp("m", v1.PolicyMatch{Kinds: []string{"Silo"}, Operations: []string{"DELETE"}}, v1.Mutation{Field: "spec.x", Value: "1"}), "want CREATE or UPDATE"},
		{mp("m", v1.PolicyMatch{Kinds: []string{"Silo"}}, v1.Mutation{Field: "status.phase", Value: "'x'"}), "can't set status"},
		{mp("m", v1.PolicyMatch{Kinds: []string{"Silo"}}, v1.Mutation{Field: "metadata.name", Value: "'x'"}), "only labels and annotations"},
		{mp("m", v1.PolicyMatch{Kinds: []string{"Silo"}}, v1.Mutation{Field: "kind", Value: "'x'"}), "can't set kind"},
		{mp("m", v1.PolicyMatch{Kinds: []string{"Silo"}}, v1.Mutation{Field: "spec..x", Value: "'x'"}), "dotted path"},
		{mp("m", v1.PolicyMatch{Kinds: []string{"Silo"}}, v1.Mutation{Field: "spec.x", Value: "1 +"}), "spec.mutations[0].value"},
	} {
		if err := CheckMutationPolicy(tc.p); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v, want %q", tc.p.Spec, err, tc.want)
		}
	}
	if err := CheckValidationPolicy(untrusted); err != nil {
		t.Error(err)
	}
}
