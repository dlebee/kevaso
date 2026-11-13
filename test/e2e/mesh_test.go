//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed"
)

// TestManyHosts is M5's "done when": example 02 (a control plane that runs no silos and a separate
// worker-only host) plus boxes behind NAT, on four real machines:
//
//	cp-1     control plane, on the shared network ("public")
//	worker-1 worker with KVM, shared network: runs the example's silo
//	home     worker behind NAT (only dials out)
//	office   worker behind NAT
//
// Every host reaches every other over the WireGuard mesh; home ↔ office goes through the relay
// (cp-1), end to end inside it, so the relay sees only encrypted UDP; and a host that goes dark is
// marked lost.
func TestManyHosts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	d, arch := driver(t)
	sshd, ok := d.(testbed.SSHAccess)
	if !ok {
		t.Skip("needs a driver with SSH access (Lima)")
	}
	if os.Getenv("LIMA_HOME") == "" {
		real, _ := os.UserHomeDir()
		t.Setenv("LIMA_HOME", filepath.Join(real, ".lima"))
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KVO_CONFIG", filepath.Join(home, ".kevaso", "config.yaml"))
	t.Setenv("KVO_TOKEN_STORE", "file")
	t.Setenv("KVO_SERVER", "")

	run := testbed.NewRunID()
	specs := map[string]testbed.Spec{
		"cp":     {Role: "cp", CPUs: 2, Memory: "2GiB", Disk: "10GiB", Shared: true},
		"worker": {Role: "w1", CPUs: 4, Memory: "6GiB", Disk: "60GiB", KVM: true, Shared: true},
		"home":   {Role: "home", CPUs: 1, Memory: "1GiB", Disk: "10GiB", Shared: true},
		"office": {Role: "office", CPUs: 1, Memory: "1GiB", Disk: "10GiB", Shared: true},
	}
	machines := map[string]testbed.Machine{}
	var mu sync.Mutex
	t.Cleanup(func() {
		if os.Getenv("KEVASO_E2E_KEEP") != "" {
			t.Logf("KEEPING the run's machines (limactl list | grep %s)", run)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for _, s := range specs {
			m := testbed.Machine{Name: testbed.MachineName(run, s.Role), Run: run, Role: s.Role}
			if err := d.Delete(ctx, m); err != nil {
				t.Errorf("teardown %s: %v", m.Name, err)
			}
		}
	})
	var wg sync.WaitGroup
	errs := make(chan error, len(specs))
	for name, s := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := d.Create(ctx, run, s)
			if err != nil {
				errs <- fmt.Errorf("create %s: %w", name, err)
				return
			}
			mu.Lock()
			machines[name] = m
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	sh := func(name string, cmd string) (string, error) {
		return d.Exec(ctx, machines[name], "sudo", "sh", "-c", cmd)
	}
	sharedIP := func(name string) string {
		out, err := sh(name, `ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1`)
		if err != nil || strings.TrimSpace(out) == "" {
			t.Fatalf("%s's shared address: %q %v", name, out, err)
		}
		return strings.TrimSpace(out)
	}
	cpIP, workerIP := sharedIP("cp"), sharedIP("worker")
	t.Logf("cp-1 %s, worker-1 %s, home and office behind NAT", cpIP, workerIP)
	// "Behind NAT": what a home router does to inbound traffic on the outside link. Nothing
	// unsolicited gets in on eth0 (SSH stays open, as a provider console would); replies to what
	// the box sent do (E024's setup). Traffic inside the mesh's tunnels isn't the router's business.
	for _, n := range []string{"home", "office"} {
		if out, err := sh(n, `nft -f - <<'NFT'
table inet natsim {
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "eth0" ct state established,related accept
    iifname "eth0" tcp dport 22 accept
    iifname "eth0" drop
  }
}
NFT`); err != nil {
			t.Fatalf("NAT simulation on %s: %v %s", n, err, out)
		}
	}
	// Check it: cp-1 can't reach home unsolicited.
	homeIP := sharedIP("home")
	if out, err := sh("cp", "ping -c1 -W2 "+homeIP); err == nil {
		t.Fatalf("home isn't behind NAT: cp-1 pinged it: %s", out)
	}

	bin := filepath.Join(t.TempDir(), "kevasod")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	type cmd func(context.Context, []string, io.Reader, io.Writer, io.Writer) int
	must := func(f cmd, stdin string, args ...string) string {
		t.Helper()
		var o, e bytes.Buffer
		if code := f(ctx, args, strings.NewReader(stdin), &o, &e); code != 0 {
			t.Fatalf("%v: exit %d\n%s%s", args, code, o.String(), e.String())
		}
		return o.String()
	}
	sshArgs := func(name string) []string {
		info, err := sshd.SSH(ctx, machines[name])
		if err != nil {
			t.Fatal(err)
		}
		out, err := d.Exec(ctx, machines[name], "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub")
		if err != nil {
			t.Fatal(err)
		}
		return []string{info.User + "@" + info.Host, "--ssh-port", strconv.Itoa(info.Port), "--ssh-key", info.KeyFile,
			"--host-key", strings.Fields(out)[1], "--kevasod", bin}
	}

	// The control plane, advertising its shared address (the mesh endpoint and what hosts dial).
	t.Logf("%s", must(kvoadm.Run, "", append(append([]string{"init"}, sshArgs("cp")...),
		"--name", "cp-1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--internal-ip", cpIP)...))
	server := "https://" + cpIP + ":6443"
	t.Logf("%s", must(kvoadm.Run, "", append(append([]string{"host", "add"}, sshArgs("worker")...),
		"--name", "worker-1", "--install", "worker", "--internal-ip", workerIP, "--server", server, "--loop-storage", "40G",
		"--region", "lab", "--label", "kvm=yes")...))
	for _, n := range []string{"home", "office"} {
		t.Logf("%s", must(kvoadm.Run, "", append(append([]string{"host", "add"}, sshArgs(n)...),
			"--name", n, "--install", "worker", "--runtime", "none", "--behind-nat", "--server", server, "--region", "home")...))
	}
	t.Logf("kvoadm host list:\n%s", must(kvoadm.Run, "", "host", "list"))

	// The mesh: everyone's addresses.
	hostsByName := map[string]*v1.Host{}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		var o, e bytes.Buffer
		kvo.Run(ctx, []string{"get", "hosts", "-o", "json"}, nil, &o, &e)
		hostsByName = parseHosts(t, o.Bytes())
		all := len(hostsByName) == 4
		for _, h := range hostsByName {
			all = all && h.Status.Network.PublicKey != "" && h.Status.Network.MeshIP != ""
		}
		if all {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("hosts never all published mesh keys:\n%s", o.String())
		}
		time.Sleep(3 * time.Second)
	}
	ip := func(host string) string { return hostsByName[host].Status.Network.MeshIP }
	machineOf := map[string]string{"cp-1": "cp", "worker-1": "worker", "home": "home", "office": "office"}
	ping := func(from, to string) error {
		var out string
		var err error
		for attempt := 0; attempt < 20; attempt++ { // handshakes, keepalives and plans settle
			if out, err = sh(machineOf[from], "ping -c1 -W2 "+to); err == nil {
				return nil
			}
			time.Sleep(3 * time.Second)
		}
		wgShow, _ := sh(machineOf[from], "wg show 2>/dev/null || ip -d link show kevaso0")
		return fmt.Errorf("%s → %s: %v\n%s\n%s", from, to, err, out, wgShow)
	}
	names := []string{"cp-1", "worker-1", "home", "office"}
	for _, a := range names {
		for _, b := range names {
			if a != b {
				if err := ping(a, ip(b)); err != nil {
					t.Error(err)
				}
			}
		}
	}
	// home ↔ office end to end: on the inner tunnel, through cp-1, which sees only UDP.
	innerOffice := hostsByName["office"].Status.Network.InnerIP
	go func() { _, _ = sh("home", "ping -c 8 -i 0.5 "+innerOffice) }()
	capture, _ := sh("cp", "timeout 5 tcpdump -nni kevaso0 -c 40 2>/dev/null || true")
	t.Logf("relay's view (kevaso0 on cp-1):\n%s", capture)
	if err := ping("home", innerOffice); err != nil {
		t.Errorf("home → office end to end: %v", err)
	}
	if strings.Contains(capture, "ICMP") {
		t.Errorf("the relay saw home ↔ office ICMP in the clear:\n%s", capture)
	}
	if !strings.Contains(capture, ".51821") {
		t.Errorf("no inner-tunnel UDP through the relay:\n%s", capture)
	}

	// Example 02: the silo lands on worker-1, the only worker that can run it.
	must(kvo.Run, `
apiVersion: kevaso/v1
kind: Namespace
metadata: { name: demo }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: hello, namespace: demo }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 1Gi }
  disk: { size: 10Gi }
`, "apply", "-f", "-")
	deadline = time.Now().Add(30 * time.Minute)
	for {
		var o bytes.Buffer
		kvo.Run(ctx, []string{"get", "silo", "hello", "-n", "demo", "-o", "yaml"}, nil, &o, io.Discard)
		y := o.String()
		if strings.Contains(y, "phase: Running") {
			if !strings.Contains(y, "host: worker-1") || !strings.Contains(y, "address: "+strings.TrimSuffix(hostsByName["worker-1"].Status.Network.SiloSubnet, "0/24")) {
				t.Fatalf("ran, but not as expected:\n%s", y)
			}
			break
		}
		if time.Now().After(deadline) || strings.Contains(y, "phase: Failed") {
			j, _ := sh("worker", "journalctl -u kevasod -n 40 --no-pager")
			t.Fatalf("example 02's silo:\n%s\nworker-1:\n%s", y, j)
		}
		time.Sleep(10 * time.Second)
	}
	if o := must(kvo.Run, "", "exec", "silo", "hello", "-n", "demo", "--", "hostname"); strings.TrimSpace(o) != "hello" {
		t.Fatalf("exec through worker-1's tunnel: %q", o)
	}

	// A host that goes dark is lost (lease 40s).
	if _, err := sh("office", "systemctl stop kevasod"); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Minute)
	for {
		out := must(kvoadm.Run, "", "host", "list")
		if strings.Contains(out, "office") && strings.Contains(out, "no heartbeat") {
			t.Logf("after stopping office:\n%s", out)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("office never marked lost:\n%s", out)
		}
		time.Sleep(5 * time.Second)
	}
}

func parseHosts(t *testing.T, data []byte) map[string]*v1.Host {
	t.Helper()
	out := map[string]*v1.Host{}
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		// kvo get -o json prints the items as a JSON array
		var items []json.RawMessage
		if json.Unmarshal(data, &items) != nil {
			return out
		}
		list.Items = items
	}
	for _, raw := range list.Items {
		var h v1.Host
		if json.Unmarshal(raw, &h) == nil {
			out[h.Name] = &h
		}
	}
	return out
}
