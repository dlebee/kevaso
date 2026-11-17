package e2e

import (
	"testing"
)

func TestMetalAPIPort(t *testing.T) {
	t.Setenv("KEVASO_METAL_API_PORT", "")
	got, err := metalAPIPort()
	if err != nil || got != "6443" {
		t.Fatalf("unset: %q %v", got, err)
	}
	t.Setenv("KEVASO_METAL_API_PORT", "21143")
	got, err = metalAPIPort()
	if err != nil || got != "21143" {
		t.Fatalf("slot port: %q %v", got, err)
	}
	if metalAPIServer("203.0.113.10", got) != "https://203.0.113.10:21143" {
		t.Fatal(metalAPIServer("203.0.113.10", got))
	}
	if metalAPIServerFor("203.0.113.10", "198.51.100.1", "6443") != "https://203.0.113.10:6443" {
		t.Fatal(metalAPIServerFor("203.0.113.10", "198.51.100.1", "6443"))
	}
	if metalAPIServerFor("10.88.1.11", "203.0.113.1", "21143") != "https://203.0.113.1:21143" {
		t.Fatal(metalAPIServerFor("10.88.1.11", "203.0.113.1", "21143"))
	}
	if ports := metalAPIDropPorts("6443"); len(ports) != 1 || ports[0] != "6443" {
		t.Fatalf("real pair drops one port: %v", ports)
	}
	ports := metalAPIDropPorts("21143")
	if len(ports) != 2 || ports[0] != "21143" || ports[1] != "6443" {
		t.Fatalf("a lab drops the slot port and the advertised port: %v", ports)
	}
	for _, bad := range []string{"0", "65536", "nope", "6443 "} {
		t.Setenv("KEVASO_METAL_API_PORT", bad)
		if _, err := metalAPIPort(); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
