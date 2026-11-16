package e2e

import (
	"strconv"
	"testing"

	"kevaso.com/core/testbed/lab"
)

func TestMetalDialPort(t *testing.T) {
	t.Setenv("KEVASO_METAL_PORT_80", "")
	got, err := metalDialPort(80)
	if err != nil || got != 80 {
		t.Fatalf("unset: %d %v", got, err)
	}
	t.Setenv("KEVASO_METAL_PORT_80", "21180")
	got, err = metalDialPort(80)
	if err != nil || got != 21180 {
		t.Fatalf("slot port: %d %v", got, err)
	}
	t.Setenv("KEVASO_METAL_PORT_18210", "21127")
	got, err = metalDialPort(18210)
	if err != nil || got != 21127 {
		t.Fatalf("mesh: %d %v", got, err)
	}
	for _, bad := range []string{"0", "65536", "nope", "80 "} {
		t.Setenv("KEVASO_METAL_PORT_443", bad)
		if _, err := metalDialPort(443); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if _, err := metalDialPort(0); err == nil {
		t.Fatal("port 0 was accepted")
	}
	for _, d := range lab.PairDials() {
		t.Setenv("KEVASO_METAL_PORT_"+strconv.Itoa(d.Port), "")
	}
	if err := metalDialPorts(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEVASO_METAL_PORT_80", "nope")
	if err := metalDialPorts(); err == nil {
		t.Fatal("a bad HTTP port was accepted")
	}
}
