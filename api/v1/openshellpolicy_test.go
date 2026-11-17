package v1

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
)

func TestOpenShellHost(t *testing.T) {
	ok := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"Example.COM.", "example.com"},
		{"*.example.com", "*.example.com"},
		{"8.8.8.8", "8.8.8.8"},
		{"8.8.8.8/32", "8.8.8.8"},
		{"198.51.100.10", "198.51.100.10"},
	}
	for _, c := range ok {
		got, err := OpenShellHost(c.in)
		if err != nil || got != c.want {
			t.Errorf("OpenShellHost(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	closed := []struct{ in, rng string }{
		{"10.64.2.5", "10.64.0.0/16"},
		{"10.64.0.0/16", "the silo range"},
		{"10.65.0.9", "the service range"},
		{"10.63.0.4", "the mesh range"},
		{"10.62.0.4", "the mesh range"},
		{"127.0.0.1", "loopback"},
		{"127.0.0.0/8", "loopback"},
		{"169.254.169.254", "link-local"},
		{"::1", "loopback"},
		{"fe80::1", "link-local"},
	}
	for _, c := range closed {
		_, err := OpenShellHost(c.in)
		if err == nil || !strings.Contains(err.Error(), c.rng) {
			t.Errorf("OpenShellHost(%q) = %v; want a refusal naming %s", c.in, err, c.rng)
		}
	}
	for _, in := range []string{"10.1.2.3", "192.168.1.1", "172.16.5.5", "100.64.0.1"} {
		_, err := OpenShellHost(in)
		if err == nil || !strings.Contains(err.Error(), "hosts are names or public addresses") {
			t.Errorf("OpenShellHost(%q) = %v; want hosts are names or public addresses", in, err)
		}
	}
	for _, in := range []string{"8.8.8.8/24", "10.0.0.0/8", "0.0.0.0/0"} {
		_, err := OpenShellHost(in)
		if err == nil || !strings.Contains(err.Error(), "not a range") {
			t.Errorf("OpenShellHost(%q) = %v; want not a range", in, err)
		}
	}
	if _, err := OpenShellHost("2001:db8::1"); err == nil || !strings.Contains(err.Error(), "IPv6 comes later") {
		t.Errorf("IPv6: %v", err)
	}
}

func TestPoliciesForSkipsAMissingName(t *testing.T) {
	s := &Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "box"}, Spec: SiloSpec{OpenShellPolicies: []string{"b", "gone", "a"}}}
	all := []*OpenShellPolicy{
		{ObjectMeta: meta.ObjectMeta{Namespace: "other", Name: "b"}},
		{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "a"}},
		{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "b"}},
	}
	got := PoliciesFor(s, all)
	if len(got) != 2 || got[0].Name != "b" || got[1].Name != "a" {
		var names []string
		for _, p := range got {
			names = append(names, p.Namespace+"/"+p.Name)
		}
		t.Fatalf("PoliciesFor = %v, want dev/b then dev/a", names)
	}
}

func TestOpenShellPath(t *testing.T) {
	for _, p := range []string{"/", "/**", "/usr/bin/curl", "/v1/*"} {
		if !OpenShellPath(p) {
			t.Errorf("%q should be a path", p)
		}
	}
	for _, p := range []string{"", "relative", "/a/../b", "/a/b\n", "/" + strings.Repeat("a", 200)} {
		if OpenShellPath(p) {
			t.Errorf("%q should be refused", p)
		}
	}
}
