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

func TestMetalLabHost(t *testing.T) {
	t.Setenv("KEVASO_METAL_HOST", "")
	got, err := metalLabHost()
	if err != nil || got != "" {
		t.Fatalf("unset: %q %v", got, err)
	}
	t.Setenv("KEVASO_METAL_HOST", "ubuntu@203.0.113.1:21122")
	got, err = metalLabHost()
	if err != nil || got != "203.0.113.1" {
		t.Fatalf("lab host: %q %v", got, err)
	}
	t.Setenv("KEVASO_METAL_HOST", "not a host")
	if _, err := metalLabHost(); err == nil {
		t.Fatal("a host with a space was accepted")
	}
}

func TestMetalDialTarget(t *testing.T) {
	t.Setenv("KEVASO_METAL_PORT_80", "")
	t.Setenv("KEVASO_METAL_PORT_18200", "")
	t.Setenv("KEVASO_METAL_EXTERNAL_IP", "")
	t.Setenv("KEVASO_METAL2_EXTERNAL_IP", "")
	got, err := metalDialTarget("203.0.113.10", "203.0.113.1", 80)
	if err != nil || got != "203.0.113.10:80" {
		t.Fatalf("a real machine: %s %v", got, err)
	}

	t.Setenv("KEVASO_METAL_PORT_80", "21180")
	t.Setenv("KEVASO_METAL_PORT_18200", "21125")
	t.Setenv("KEVASO_METAL_EXTERNAL_IP", "10.88.1.11")
	t.Setenv("KEVASO_METAL2_EXTERNAL_IP", "10.88.1.12")
	got, err = metalDialTarget("10.88.1.11", "203.0.113.1", 80)
	if err != nil || got != "203.0.113.1:21180" {
		t.Fatalf("m1's published port: %s %v", got, err)
	}
	got, err = metalDialTarget("10.88.1.12", "203.0.113.1", 18200)
	if err != nil || got != "203.0.113.1:21125" {
		t.Fatalf("m2's published port: %s %v", got, err)
	}
	// The slot port is forwarded to m2. A check of m1 dials m1's own address
	// on the real port, which this Mac does not route.
	got, err = metalDialTarget("10.88.1.11", "203.0.113.1", 18200)
	if err != nil || got != "10.88.1.11:18200" {
		t.Fatalf("the other machine: %s %v", got, err)
	}
	if _, err := metalDialTarget("10.88.1.11", "", 80); err == nil {
		t.Fatal("a published port with no lab host was accepted")
	}
}
