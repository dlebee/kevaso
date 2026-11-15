package hostreset

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kri/openshell"
	"kevaso.com/core/sdk/kri"
)

// Item 7, K-101: a reset left OpenShell behind: the gateways' kvos-* users (members of docker,
// which is root on the host, or kvm) and their groups, the Docker driver's sandbox containers on
// a Docker that isn't Kevaso's, and a gateway process. The plan removes them; the checklist
// looks for each.
func TestTheResetLeavesNothingOfOpenShell(t *testing.T) {
	g := openshell.Gateway{Key: "docker-host", Port: openshell.BasePort, Driver: openshell.DriverDocker}
	if !strings.HasPrefix(g.User(), openshell.UserPrefix) {
		t.Fatalf("gateway user %s doesn't start with %s", g.User(), openshell.UserPrefix)
	}
	if !strings.HasPrefix(openshell.SandboxName(kri.ID{Namespace: "dev", Name: "a", UID: "u1"}), "kv-") {
		t.Fatal("sandbox names changed: the reset's container pattern must follow")
	}
	users := ""
	for _, s := range Plan(PlanInput{}) {
		if strings.Contains(s.Script, "userdel") {
			users += s.Script
		}
	}
	if !strings.Contains(users, "kvos-") || !strings.Contains(users, "groupdel") {
		t.Fatalf("no step removes the kvos-* users and groups:\n%s", users)
	}
	r, _ := runStep(t, PlanInput{DockerOurs: false}, "remove OpenShell's sandbox containers")
	rm := ""
	for _, c := range r.calls("docker") {
		if len(c) > 0 && c[0] == "rm" {
			rm += strings.Join(c, " ") + "\n"
		}
	}
	if !strings.Contains(rm, "osc1") || strings.Contains(rm, "other-") {
		t.Fatalf("removed %q: want the OpenShell sandbox container (osc1) only", rm)
	}
	all := ""
	for _, c := range Checklist(CheckOptions{}) {
		all += c.Name + "\n" + c.Script + "\n"
	}
	for _, want := range []string{"kvos-", "openshell-gateway", "kv-[0-9a-f]{10}", "docker", "kvm"} {
		if !strings.Contains(all, want) {
			t.Errorf("no check looks for %q", want)
		}
	}
}

// Item 7: the inspection didn't see OpenShell silos, so a reset went ahead on a host that had
// them without --force. It lists them from the runtime's state on disk (their gateways may be
// down: item 1).
func TestInspectFindsOpenShellSilos(t *testing.T) {
	if !strings.Contains(InspectScript, openShellSiloLines(openshell.StateDir)) {
		t.Fatal("InspectScript doesn't list OpenShell silos")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/silos", 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(map[string]any{"id": kri.ID{Namespace: "dev", Name: "agent", UID: "u1"}, "created": true}, "", "  ")
	if err := os.WriteFile(dir+"/silos/kv-x.json", b, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/sh", "-c", openShellSiloLines(dir)).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "openshell dev/agent" {
		t.Fatalf("listed %q (%v), want %q", out, err, "openshell dev/agent")
	}
}
