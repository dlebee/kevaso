package kvoadm

import (
	"strings"
	"testing"
)

func TestOperatorUnit(t *testing.T) {
	u := OperatorUnit("sessions")
	for _, want := range []string{
		"ExecStart=/usr/local/bin/kevaso-plugin-sessions\n", "DynamicUser=yes", "StateDirectory=kevaso-plugin-sessions",
		"LoadCredential=token.json:/etc/kevaso/plugins/sessions/token.json", "LoadCredential=server:/etc/kevaso/plugins/sessions/server",
		"CapabilityBoundingSet=\n", "NoNewPrivileges=yes",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	if strings.Contains(u, "Environment") || strings.Contains(u, "--token") {
		t.Errorf("credentials outside LoadCredential:\n%s", u)
	}
	o, err := parseOperator([]string{"root@cp1", "--package", "p", "--yes", "--adopt"})
	if err != nil || o.pkg != "p" || !o.yes || !o.adopt || o.withTarget(o.rest[0]).Address != "cp1" {
		t.Errorf("parse: %+v %v", o, err)
	}
}
