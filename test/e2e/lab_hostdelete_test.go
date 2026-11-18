//go:build metal

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/container"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/sdk/kri"
)

// TestLabHostDelete deletes a worker while its kevasod is running and checks the outcomes:
// a silo that can be recreated runs on the other worker, a silo with a local volume stays
// unschedulable, and the deleted host's silos stop on that machine within a minute with
// their disks and volumes still there. kvoadm host add joins it again without anyone
// moving /var/lib/kevaso/pki aside by hand.
//
// Source a pair lab's env file first (testbed/lab/.labs/NAME/env.sh). Without LAB_NAME the test
// skips, which keeps it out of a bare-metal run. It uses the two-machine cluster (metal2, the
// same helpers as TestMetal2*), so run it on its own or with those tests, not with the
// one-machine suite.
//
// The pair is left usable. kvoadm host add runs the way setUpPair adds the worker, and the
// placement label is put back.
func TestLabHostDelete(t *testing.T) {
	if os.Getenv("LAB_NAME") == "" {
		t.Skip("LAB_NAME is unset: source testbed/lab/.labs/NAME/env.sh (a pair lab; this test uses metal2)")
	}
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	const ns = "kvthd"
	c.namespace(ns)
	// mover has no hostSelector, so it can be placed elsewhere after the delete: machine 1 is
	// cordoned while it is placed, then uncordoned.
	p.kvoadm("host", "drain", metalHost)
	t.Cleanup(func() { p.kvoadm("host", "uncordon", metalHost) })
	c.apply(boxEcho(ns, "mover", 8080) + "  availability: { onHostLoss: Recreate }\n---\n" +
		vmEcho(ns, "pin", 8080) + on(metalHost2) + "  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n")
	for _, name := range []string{"mover", "pin"} {
		c.eventually(name+" running on "+metalHost2, 5*time.Minute, func() (bool, string) {
			s := c.silo(ns, name)
			return s.Status.Host == metalHost2 && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
		})
	}

	p.kvoadm("host", "uncordon", metalHost)
	mover := c.silo(ns, "mover")
	pin := c.silo(ns, "pin")
	mn := container.NamesFor(kri.ID{Namespace: mover.Namespace, Name: mover.Name, UID: mover.UID})
	pn := cloudhypervisor.NamesFor(kri.ID{Namespace: pin.Namespace, Name: pin.Name, UID: pin.UID})
	c.must("", "delete", "host", metalHost2, "--confirm-off")
	c.eventually(metalHost2+" stopped its silos and kept their disks", time.Minute, func() (bool, string) {
		out, err := p.c2.sh(fmt.Sprintf("set +e; echo unit:$(systemctl is-active %s || true); echo docker:$(docker inspect -f '{{.State.Status}}' %s 2>/dev/null || echo missing); lvs --noheadings -o lv_name kevaso; echo ---; journalctl -u kevasod --no-pager --since '-3min' | grep -F 'was removed from the cluster' || true; exit 0", pn.Unit, mn.Main))
		if err != nil {
			return false, err.Error()
		}
		unitDown := strings.Contains(out, "unit:inactive") || strings.Contains(out, "unit:failed")
		dockerDown := strings.Contains(out, "docker:exited") || strings.Contains(out, "docker:dead") || strings.Contains(out, "docker:missing")
		root, vol := false, false
		for _, f := range strings.Fields(out) {
			if f == pn.LV {
				root = true
			}
			if strings.HasPrefix(f, pn.LV+"-") {
				vol = true
			}
		}
		said := strings.Contains(out, "was removed from the cluster")
		return unitDown && dockerDown && root && vol && said, strings.TrimSpace(out)
	})
	c.eventually("mover running on "+metalHost, 5*time.Minute, func() (bool, string) {
		s := c.silo(ns, "mover")
		return s.Status.Host == metalHost && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
	})
	c.eventually("pin unschedulable after "+metalHost2+" was deleted", 2*time.Minute, func() (bool, string) {
		s := c.silo(ns, "pin")
		cond := meta.FindCondition(s.Status.Conditions, "Unschedulable")
		ok := s.Status.Host == metalHost2 && cond != nil && cond.Status == meta.ConditionTrue && cond.Reason == "HostDeleted"
		msg := s.Status.Host
		if cond != nil {
			msg = s.Status.Host + " " + cond.Reason + " " + cond.Message
		}
		return ok, msg
	})

	bin := p.bin
	if bin == "" {
		arch := p.m2.arch
		if arch == "" {
			arch = "amd64"
		}
		var err error
		bin, err = buildKevasod(c.ctx, arch)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg1, cfg2 := p.m1.cfg, p.m2.cfg
	ssh := []string{cfg2.SSHTarget(), "--ssh-port", strconv.Itoa(cfg2.Port), "--ssh-key", cfg2.KeyFile, "--host-key", cfg2.HostKey, "--kevasod", bin, "--no-extra-hardening"}
	storage := []string{"--loop-storage", metalLoop}
	if cfg2.SpareDisk != "" {
		storage = []string{"--storage-device", cfg2.SpareDisk}
	}
	if out, err := p.c2.sh("test -f /etc/kevaso/test-internet-ca.pem && echo yes"); err == nil && strings.Contains(out, "yes") {
		storage = append(storage, "--egress-extra-ca", "/etc/kevaso/test-internet-ca.pem")
	}
	add := append(append(append([]string{"host", "add"}, ssh...), "--name", metalHost2, "--install", "worker",
		"--runtime", "cloud-hypervisor", "--runtime", "docker", "--external-ip", cfg2.ExternalIP), storage...)
	if p.apiPort != "" && p.apiPort != "6443" {
		add = append(add, "--server", metalAPIServer(cfg1.ExternalIP, "6443"))
	}
	var o bytes.Buffer
	if code := kvoadm.Run(c.ctx, add, strings.NewReader(""), &o, &o); code != 0 {
		t.Fatalf("kvoadm host add %s: exit %d\n%s", metalHost2, code, o.String())
	}
	if err := waitRuntimes(c.ctx, metalHost2, "cloud-hypervisor", "docker"); err != nil {
		t.Fatal(err)
	}
	var h v1.Host
	if err := json.Unmarshal([]byte(c.must("", "get", "host", metalHost2, "-o", "json")), &h); err != nil {
		t.Fatal(err)
	}
	if h.Spec.Components.Worker == nil {
		t.Fatalf("%s came back without a worker", metalHost2)
	}
	if h.Spec.Components.Worker.Labels == nil {
		h.Spec.Components.Worker.Labels = map[string]string{}
	}
	h.Spec.Components.Worker.Labels["kvt/host"] = metalHost2
	h.Status = v1.HostStatus{}
	b, _ := json.Marshal(&h)
	c.apply(string(b))
}
