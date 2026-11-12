package testbed

import (
	"testing"
	"time"
)

func TestNewRunIDIsValidAndUnique(t *testing.T) {
	seen := map[RunID]bool{}
	for range 100 {
		r := NewRunID()
		if err := r.Validate(); err != nil {
			t.Fatalf("NewRunID() = %q: %v", r, err)
		}
		if seen[r] {
			t.Fatalf("NewRunID() repeated %q", r)
		}
		seen[r] = true
	}
}

func TestRunIDValidate(t *testing.T) {
	for _, tc := range []struct {
		id RunID
		ok bool
	}{
		{"a1b2c3", true},
		{"abcdef123456", true},
		{"abc12", false},         // too short
		{"abcdef1234567", false}, // too long
		{"ABC123", false},        // uppercase
		{"abc-123", false},       // dash would break name parsing
		{"", false},
	} {
		if err := tc.id.Validate(); (err == nil) != tc.ok {
			t.Errorf("RunID(%q).Validate() = %v, want ok=%v", tc.id, err, tc.ok)
		}
	}
}

func TestSpecValidate(t *testing.T) {
	good := Spec{Role: "w1", CPUs: 2, Memory: "4GiB", Disk: "20GiB"}
	if err := good.Validate(); err != nil {
		t.Fatalf("good spec: %v", err)
	}
	for name, s := range map[string]Spec{
		"empty role":       {Role: "", CPUs: 2, Memory: "4GiB", Disk: "20GiB"},
		"role with dash":   {Role: "w-1", CPUs: 2, Memory: "4GiB", Disk: "20GiB"},
		"role starts num":  {Role: "1w", CPUs: 2, Memory: "4GiB", Disk: "20GiB"},
		"role too long":    {Role: "workerone", CPUs: 2, Memory: "4GiB", Disk: "20GiB"},
		"no cpus":          {Role: "w1", CPUs: 0, Memory: "4GiB", Disk: "20GiB"},
		"no memory":        {Role: "w1", CPUs: 2, Disk: "20GiB"},
		"no disk":          {Role: "w1", CPUs: 2, Memory: "4GiB"},
		"everything wrong": {},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want an error", name)
		}
	}
}

func TestMachineNameRoundTrip(t *testing.T) {
	name := MachineName("a1b2c3d4", "cp")
	if name != "kvt-a1b2c3d4-cp" {
		t.Fatalf("MachineName = %q", name)
	}
	run, role, ok := ParseMachineName(name)
	if !ok || run != "a1b2c3d4" || role != "cp" {
		t.Fatalf("ParseMachineName(%q) = %q, %q, %v", name, run, role, ok)
	}
}

func TestParseMachineNameRejectsOthers(t *testing.T) {
	for _, name := range []string{
		"kvaso-e008",        // a research VM, never swept
		"oc-issue-gateway",  // someone else's VM
		"kvt-a1b2c3d4",      // missing role
		"kvt-a1b2c3d4-cp-x", // extra part
		"kvt-AB12CD-cp",     // bad run id
		"kvt-a1b2c3d4-Cp",   // bad role
		"xyz-a1b2c3d4-cp",   // other prefix
		"",
	} {
		if _, _, ok := ParseMachineName(name); ok {
			t.Errorf("ParseMachineName(%q) accepted a non-testbed name", name)
		}
	}
}

func TestLeftovers(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	ms := []Machine{
		{Name: "kvt-current1-cp", Run: "current1", Created: now.Add(-3 * time.Hour)},
		{Name: "kvt-oldrun1-cp", Run: "oldrun1", Created: now.Add(-3 * time.Hour)},
		{Name: "kvt-newrun1-cp", Run: "newrun1", Created: now.Add(-5 * time.Minute)},
		{Name: "kvt-unknown1-w1", Run: "unknown1"}, // age unknown
	}
	got := names(Leftovers(ms, "current1", now, time.Hour))
	want := []string{"kvt-oldrun1-cp", "kvt-unknown1-w1"}
	if !equal(got, want) {
		t.Fatalf("Leftovers(olderThan=1h) = %v, want %v", got, want)
	}
	got = names(Leftovers(ms, "current1", now, 0))
	want = []string{"kvt-oldrun1-cp", "kvt-newrun1-cp", "kvt-unknown1-w1"}
	if !equal(got, want) {
		t.Fatalf("Leftovers(olderThan=0) = %v, want %v", got, want)
	}
}

func names(ms []Machine) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
