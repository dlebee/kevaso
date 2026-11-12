package v1

import "testing"

func TestEgressParse(t *testing.T) {
	for _, c := range []struct {
		rule  EgressRule
		ok    bool
		host  string
		cidr  string
		ports string
	}{
		{EgressRule{To: "0.0.0.0/0", Ports: []string{"30303"}, Protocols: []string{"tcp", "udp"}}, true, "", "0.0.0.0/0", "30303"},
		{EgressRule{To: "203.0.113.7"}, true, "", "203.0.113.7/32", ""},
		{EgressRule{To: "10.1.2.3/8"}, true, "", "10.0.0.0/8", ""},
		{EgressRule{To: "API.GitHub.com."}, true, "api.github.com", "", "443"},
		{EgressRule{To: "*.github.com", Ports: []string{"443", "8443"}}, true, "*.github.com", "", "443,8443"},
		{EgressRule{To: "198.51.100.0/24", Ports: []string{"30000-30100"}}, true, "", "198.51.100.0/24", "30000-30100"},
		{EgressRule{To: "api.github.com", Protocols: []string{"udp"}}, false, "", "", ""}, // names are TLS only
		{EgressRule{To: "2001:db8::/32"}, false, "", "", ""},
		{EgressRule{To: "localhost"}, false, "", "", ""}, // not a fully qualified name
		{EgressRule{To: "bad_name.example.com"}, false, "", "", ""},
		{EgressRule{To: "0.0.0.0/0", Ports: []string{"0"}}, false, "", "", ""},
		{EgressRule{To: "0.0.0.0/0", Ports: []string{"9-3"}}, false, "", "", ""},
		{EgressRule{To: "0.0.0.0/0", Protocols: []string{"icmp"}}, false, "", "", ""},
		{EgressRule{To: ""}, false, "", "", ""},
	} {
		e, err := c.rule.Parse()
		if (err == nil) != c.ok {
			t.Errorf("%+v: err = %v", c.rule, err)
			continue
		}
		if !c.ok {
			continue
		}
		if e.Host != c.host || (c.cidr != "" && e.Prefix.String() != c.cidr) {
			t.Errorf("%+v: host %q prefix %v", c.rule, e.Host, e.Prefix)
		}
		var ports string
		for i, p := range e.Ports {
			if i > 0 {
				ports += ","
			}
			ports += p.String()
		}
		if ports != c.ports {
			t.Errorf("%+v: ports %q, want %q", c.rule, ports, c.ports)
		}
	}
}

func TestMatchHost(t *testing.T) {
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{
		{"api.github.com", "api.github.com", true},
		{"api.github.com", "API.GITHUB.COM.", true},
		{"api.github.com", "evil-api.github.com", false},
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "a.b.github.com", true},
		{"*.github.com", "github.com", false},
		{"*.github.com", "evilgithub.com", false},
		{"api.github.com", "", false},
	} {
		if got := MatchHost(c.pattern, c.name); got != c.want {
			t.Errorf("MatchHost(%q, %q) = %v", c.pattern, c.name, got)
		}
	}
}
