//go:build metal

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvoadm"
)

// TestLabHostDelete deletes a worker whose machine is stopped and checks the two outcomes:
// a silo that can be recreated runs on the other worker, and a silo with a local volume stays
// unschedulable. The stopped worker's old certificate is refused when kevasod starts again.
//
// Source a pair lab's env file first (testbed/lab/.labs/NAME/env.sh). Without LAB_NAME the test
// skips, which keeps it out of a bare-metal run. It uses the two-machine cluster (metal2, the
// same helpers as TestMetal2*), so run it on its own or with those tests, not with the
// one-machine suite.
//
// The pair is left usable. Join reuses a certificate it already has, so the old
// /var/lib/kevaso/pki host certificate is removed first; then kvoadm host add runs the way
// setUpPair adds the worker, and the placement label is put back.
func TestLabHostDelete(t *testing.T) {
	if os.Getenv("LAB_NAME") == "" {
		t.Skip("LAB_NAME is unset: source testbed/lab/.labs/NAME/env.sh (a pair lab; this test uses metal2)")
	}
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	const ns = "kvthd"
	c.namespace(ns)
	c.apply(boxEcho(ns, "mover", 8080) + on(metalHost2) + "  availability: { onHostLoss: Recreate }\n---\n" +
		boxEcho(ns, "pin", 8080) + on(metalHost2) + "  volumes: [{ name: data, size: 1Gi, mountPath: /data }]\n")
	for _, name := range []string{"mover", "pin"} {
		c.eventually(name+" running on "+metalHost2, 5*time.Minute, func() (bool, string) {
			s := c.silo(ns, name)
			return s.Status.Host == metalHost2 && s.Status.Phase == "Running", s.Status.Host + " " + s.Status.Phase
		})
	}

	p.c2.mustSh("systemctl stop kevasod")
	c.must("", "delete", "host", metalHost2, "--confirm-off")
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

	p.c2.mustSh("systemctl start kevasod")
	c.eventually("the old certificate is refused", 2*time.Minute, func() (bool, string) {
		j, err := p.c2.sh("journalctl -u kevasod --no-pager --since '-3min' | grep -F 'was removed from the cluster' || true")
		if err != nil {
			return false, err.Error()
		}
		return strings.Contains(j, "was removed from the cluster"), strings.TrimSpace(j)
	})

	// The certificate Join already stored would be reused, and the API would keep refusing it.
	p.c2.mustSh("systemctl stop kevasod && rm -f /var/lib/kevaso/pki/host.crt /var/lib/kevaso/pki/host.key")
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
