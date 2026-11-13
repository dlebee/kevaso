package kvo

import (
	"bytes"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// What a silo writes about itself (its upkeep checks' output; a host writes its runtimes' messages
// and, compromised, anything in the status of the silos on it) reaches an operator's terminal through kvo. A silo is not trusted: none of it may
// carry a terminal escape (retitle the window, rewrite the screen, hide a line) or a bidi
// override, whether kvo prints it as a table or describes the object.
const evil = "ok\x1b]0;pwned\x07\x1b[2J\x1b[1A\r\u202ehidden\u009b31m"

func clean(t *testing.T, where, out string) {
	t.Helper()
	for _, bad := range []string{"\x1b", "\x07", "\r", "\u202e", "\u009b"} {
		if strings.Contains(out, bad) {
			t.Errorf("%s: %q reached the terminal:\n%q", where, bad, out)
		}
	}
}

func evilSilo() *v1.Silo {
	s := silo()
	s.Spec.Upkeep = []v1.Upkeep{{Name: "disk", Every: "6h", Check: "df", Fix: "x"}}
	s.Spec.Daemons = []v1.Daemon{{Name: "app", Run: "x"}}
	s.Status.Upkeep = []v1.UpkeepStatus{{Name: "disk", State: v1.UpkeepFailed, Message: evil}}
	s.Status.Daemons = []v1.DaemonStatus{{Name: "app", State: evil}}
	s.Status.Init = append(s.Status.Init, v1.StepStatus{Name: "evil", State: evil})
	s.Status.Conditions = append(s.Status.Conditions, meta.Condition{Type: "Upkeep", Status: meta.ConditionFalse, Reason: "Failed", Message: evil})
	return s
}

func TestDescribeKeepsSiloTextOutOfTheTerminal(t *testing.T) {
	var b bytes.Buffer
	if err := describeObject(&b, evilSilo()); err != nil {
		t.Fatal(err)
	}
	clean(t, "describe silo", b.String())
	if !strings.Contains(b.String(), "hidden") {
		t.Errorf("the text itself is gone:\n%s", b.String())
	}
	h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "hv1"}, Spec: v1.HostSpec{Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}},
		Status: v1.HostStatus{Runtimes: map[string]v1.RuntimeStatus{"docker": {State: "Failed", Message: evil}}}}
	b.Reset()
	_ = describeObject(&b, h)
	clean(t, "describe host", b.String())
}

func TestTablesKeepSiloTextOutOfTheTerminal(t *testing.T) {
	k, _ := v1.Lookup("Silo")
	var b bytes.Buffer
	if err := printTable(&b, k, []meta.Object{evilSilo()}, false, true); err != nil {
		t.Fatal(err)
	}
	clean(t, "get silos -o wide", b.String())
	if got := summary(evilSilo()); strings.ContainsAny(got, "\x1b\x07\r") {
		t.Errorf("summary: %q", got)
	}
}

func TestTerminalSafeKeepsText(t *testing.T) {
	var b bytes.Buffer
	in := "naïve\t日本語 → ok\n"
	if n, err := safeTerminal(&b).Write([]byte(in + "\x1b[31m\x00\xff")); err != nil || n != len(in)+7 || b.String() != in+"[31m" {
		t.Fatalf("%d %v %q", n, err, b.String())
	}
}
