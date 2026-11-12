package acme

import (
	"encoding/json"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func TestPick(t *testing.T) {
	all := SolverConfig{HTTP01: &HTTP01{}}
	zone := SolverConfig{Selector: &Selector{DNSZones: []string{"example.com"}}, DNS01: &DNS01{Provider: "a"}}
	sub := SolverConfig{Selector: &Selector{DNSZones: []string{"internal.example.com"}}, DNS01: &DNS01{Provider: "b"}}
	exact := SolverConfig{Selector: &Selector{DNSNames: []string{"www.internal.example.com"}}, HTTP01: &HTTP01{}}
	solvers := []SolverConfig{all, zone, sub, exact}
	for host, want := range map[string]string{
		"other.org":                "http01-all",
		"example.com":              "a",
		"api.example.com":          "a",
		"*.example.com":            "a",
		"db.internal.example.com":  "b",
		"www.internal.example.com": "exact",
		"notexample.com":           "http01-all",
	} {
		sc, ok := Pick(solvers, host)
		got := "none"
		switch {
		case !ok:
		case sc.DNS01 != nil:
			got = sc.DNS01.Provider
		case sc.Selector != nil:
			got = "exact"
		default:
			got = "http01-all"
		}
		if got != want {
			t.Errorf("%s: %s, want %s", host, got, want)
		}
	}
	if _, ok := Pick([]SolverConfig{zone}, "other.org"); ok {
		t.Error("a host outside every selector got a solver")
	}
}

// The API's acme shorthand must decode as this controller's config.
func TestAPIShape(t *testing.T) {
	b, _ := json.Marshal(v1.ACMEIssuer{Server: "https://acme/dir", Solvers: []v1.ACMESolver{
		{Selector: &v1.ACMESelector{DNSZones: []string{"example.com"}}, DNS01: &v1.ACMEDNS01{Provider: "cf", PropagationSeconds: 5}},
		{HTTP01: &v1.ACMEHTTP01{}},
	}})
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if c.Server != "https://acme/dir" || len(c.Solvers) != 2 || c.Solvers[0].DNS01.Provider != "cf" || c.Solvers[0].DNS01.PropagationSeconds != 5 ||
		c.Solvers[0].Selector.DNSZones[0] != "example.com" || c.Solvers[1].HTTP01 == nil {
		t.Fatalf("%s decoded as %+v", b, c)
	}
}

func TestCheckSolver(t *testing.T) {
	c := &Controller{DNSProviders: map[string]DNSProvider{}}
	for _, sc := range []SolverConfig{{}, {HTTP01: &HTTP01{}, DNS01: &DNS01{}}, {HTTP01: &HTTP01{}}, {DNS01: &DNS01{Provider: "missing"}}} {
		if c.checkSolver(sc) == nil {
			t.Errorf("%+v accepted", sc)
		}
	}
}
