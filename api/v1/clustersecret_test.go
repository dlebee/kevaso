package v1

import "testing"

// ForHost is the value-route rule: plugins must be set, and hosts empty means every host,
// otherwise only a named one. A blank host name is nobody.
func TestClusterSecretForHost(t *testing.T) {
	all := &ClusterSecret{Spec: ClusterSecretSpec{Plugins: []string{"juicefs"}}}
	if !all.ForHost("hv1") || !all.ForHost("cp1") {
		t.Fatal("empty hosts is every host")
	}
	if all.ForHost("") {
		t.Fatal("an empty host name was allowed")
	}
	named := &ClusterSecret{Spec: ClusterSecretSpec{Plugins: []string{"juicefs"}, Hosts: []string{"hv1"}}}
	if !named.ForHost("hv1") {
		t.Fatal("the named host was refused")
	}
	if named.ForHost("hv2") || named.ForHost("cp1") {
		t.Fatal("a host the secret doesn't name was allowed")
	}
	for _, cs := range []*ClusterSecret{
		{Spec: ClusterSecretSpec{}},
		{Spec: ClusterSecretSpec{Plugins: nil, Hosts: []string{"hv1"}}},
		{Spec: ClusterSecretSpec{Hosts: []string{"hv1"}}},
		nil,
	} {
		if cs.ForHost("hv1") {
			t.Fatalf("plugins empty allowed %+v", cs)
		}
	}
}
