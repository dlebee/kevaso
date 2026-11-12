package apiserver

import (
	"encoding/json"
	"testing"
)

func TestIssuerSolverRules(t *testing.T) {
	v, err := newValidator(builtinRules)
	if err != nil {
		t.Fatal(err)
	}
	for spec, ok := range map[string]bool{
		`{"acme":{"server":"https://a/dir"}}`: true,
		`{"acme":{"server":"https://a/dir","solvers":[{"http01":{}},{"selector":{"dnsZones":["example.com"]},"dns01":{"provider":"cf"}}]}}`: true,
		`{"acme":{"server":"https://a/dir","solvers":[{}]}}`:                                      false,
		`{"acme":{"server":"https://a/dir","solvers":[{"http01":{},"dns01":{"provider":"cf"}}]}}`: false,
		`{"acme":{"server":"https://a/dir","solvers":[{"dns01":{}}]}}`:                            false,
		`{"controller":"certbot","config":{"anything":1}}`:                                        true,
		`{"controller":"certbot","internalCA":true}`:                                              false,
	} {
		var obj map[string]any
		if err := json.Unmarshal([]byte(`{"kind":"Issuer","metadata":{"name":"x"},"spec":`+spec+`}`), &obj); err != nil {
			t.Fatal(err)
		}
		if msgs := v.validate("Issuer", obj); (len(msgs) == 0) != ok {
			t.Errorf("%s: %v", spec, msgs)
		}
	}
}
