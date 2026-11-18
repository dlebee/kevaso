package apiserver

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// K-124: admission refuses a Grant whose egress rule names an address or CIDR inside the cluster's
// own ranges (silos, services, the mesh), loopback or link-local. The 422 names the range. A
// private address outside those ranges, a public address and a host name are still admitted.

func TestAGrantNamingClusterLoopbackOrLinkLocalIsRefused(t *testing.T) {
	v, err := newValidator(builtinRules)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{valid: v}
	closed := []struct{ to, rng string }{
		{"10.64.2.5", "10.64.0.0/16"},
		{"10.64.2.5/32", "10.64.0.0/16"},
		{"10.64.0.0/24", "10.64.0.0/16"},
		{"10.64.0.0/16", "the silo range"},
		{"10.65.0.9", "10.65.0.0/16"},
		{"10.65.0.0/16", "the service range"},
		{"10.63.0.4", "10.63.0.0/16"},
		{"10.63.0.0/16", "the mesh range"},
		{"10.62.0.4", "10.62.0.0/16"},
		{"10.62.0.0/16", "the mesh range"},
		{"127.0.0.1", "127.0.0.0/8"},
		{"127.8.9.10", "127.0.0.0/8"},
		{"127.0.0.0/8", "loopback"},
		{"169.254.169.254", "169.254.0.0/16"},
		{"169.254.169.254/32", "169.254.0.0/16"},
		{"169.254.42.1", "169.254.0.0/16"},
		{"169.254.0.0/16", "link-local"},
		{"0.0.0.0", "this network"},
		{"0.1.2.3", "this network"},
		{"0.0.0.0/8", "this network"},
		{"224.0.0.1", "multicast"},
		{"224.0.0.0/4", "multicast"},
		{"240.0.0.1", "reserved"},
		{"255.255.255.255", "reserved"},
		{"240.0.0.0/4", "reserved"},
	}
	for _, c := range closed {
		err := admitJSON(t, s, "Grant", objectOf(t, "Grant", []string{`spec.egress=[{"to":"` + c.to + `"}]`}))
		var ae *apiError
		if !errors.As(err, &ae) || ae.code != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), c.rng) {
			t.Errorf("egress %s: %v; want 422 naming %s", c.to, err, c.rng)
		}
	}
	// A rule that also names a host is refused for the closed address.
	err = admitJSON(t, s, "Grant", objectOf(t, "Grant", []string{`spec.egress=[{"to":"api.example.com"},{"to":"10.64.2.5"}]`}))
	var ae *apiError
	if !errors.As(err, &ae) || ae.code != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "10.64.0.0/16") {
		t.Errorf("mixed grant: %v; want 422 naming the silo range", err)
	}
	for _, to := range []string{
		"10.1.2.3", "10.1.2.0/24", "10.0.0.0/8", "10.66.1.1", "10.61.0.1",
		"192.168.1.1", "172.16.5.5", "100.64.0.1", "0.0.0.0/0", "198.51.100.10", "api.example.com",
	} {
		if err := admitJSON(t, s, "Grant", objectOf(t, "Grant", []string{`spec.egress=[{"to":"` + to + `"}]`})); err != nil {
			t.Errorf("egress %s was refused: %v", to, err)
		}
	}
}
