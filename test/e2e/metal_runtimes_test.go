//go:build metal

package e2e

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/container"
	"kevaso.com/core/sdk/kri"
)

// TestMetalRuntimeBounds is what a machine shows of the runtime bounds: the VMM's /run
// holds only its own socket directory, its serial log is capped, a container's log rolls,
// and host commands run under /run/kevaso.
//
// Listens on nothing outside.
func TestMetalRuntimeBounds(t *testing.T) {
	c := metal(t)
	ns := "bounds"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080))
	c.apply(boxEcho(ns, "box", 8081))
	c.waitRunning(ns, 15*time.Minute, "vm", "box")

	s := c.silo(ns, "vm")
	n := cloudhypervisor.NamesFor(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID})
	unit := c.mustSh("systemctl cat " + n.Unit)
	c.expect("the VMM's /run is private", unit, "TemporaryFileSystem=/run\n")
	c.expect("its own socket directory is mounted", unit, "BindPaths=/run/"+strings.TrimSuffix(n.Unit, ".service"))
	c.expect("chown does not follow a link", unit, "chown -h")
	c.expect("the serial log is capped", unit, "-ge 10485760")
	pid := strings.TrimSpace(c.mustSh("systemctl show -p MainPID --value " + n.Unit))
	c.mustSh("mkdir -p /run/kevaso-silo-other")
	seen := c.mustSh("nsenter -t " + pid + " -m ls /run")
	if strings.Contains(seen, "kevaso-silo-other") {
		t.Errorf("the VMM sees another runtime directory:\n%s", seen)
	}
	if !strings.Contains(seen, strings.TrimSuffix(n.Unit, ".service")) {
		t.Errorf("the VMM cannot see its own socket directory:\n%s", seen)
	}

	box := c.silo(ns, "box")
	bn := container.NamesFor(kri.ID{Namespace: box.Namespace, Name: box.Name, UID: box.UID})
	logs := c.mustSh("docker inspect -f '{{.HostConfig.LogConfig.Type}} {{.HostConfig.LogConfig.Config}}' " + bn.Main)
	c.expect("the container log rolls", logs, "json-file")
	c.expect("the container log is capped", logs, "max-size:10m")

	dir := strings.TrimSpace(c.mustSh("ls -d /run/kevaso/kevaso-hostexec-*"))
	if strings.Contains(dir, "/tmp/") || dir == "" {
		t.Errorf("host commands run in %q", dir)
	}
}
