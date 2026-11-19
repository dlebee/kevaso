package kvoadm

import (
	"strings"
	"testing"
)

func TestUpgradeRefusesABinaryWithNoVersion(t *testing.T) {
	for _, stamped := range []string{"", "v0.0.0-dev"} {
		if _, err := UpgradeTarget(stamped, "v0.3.1"); err == nil || !strings.Contains(err.Error(), "no version") {
			t.Fatalf("stamped %q: %v", stamped, err)
		}
		if _, err := UpgradeTarget(stamped, ""); err == nil || !strings.Contains(err.Error(), "no version") {
			t.Fatalf("stamped %q with no flag: %v", stamped, err)
		}
	}
	got, err := UpgradeTarget("v0.3.1", "v0.3.1")
	if err != nil || got != "v0.3.1" {
		t.Fatalf("matching flag: %s %v", got, err)
	}
	got, err = UpgradeTarget("v0.3.1", "")
	if err != nil || got != "v0.3.1" {
		t.Fatalf("no flag: %s %v", got, err)
	}
	if _, err := UpgradeTarget("v0.3.1", "v9.9.9"); err == nil || !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), "v0.3.1") {
		t.Fatalf("different flag: %v", err)
	}
}
