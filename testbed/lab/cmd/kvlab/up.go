package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/internal/sshboot"
	"kevaso.com/core/testbed/lab"
	"kevaso.com/core/testbed/remote"
)

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	recreate := fs.Bool("recreate", false, "replace an existing lab of this name")
	pair := fs.Bool("pair", false, "two machine VMs (m1, m2), Kevaso not installed, for the two-machine metal tests")
	name := nameFlag(args, fs)
	if err := lab.ValidName(name); err != nil {
		return err
	}
	nodes := lab.Nodes()
	if *pair {
		nodes = lab.PairNodes()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	clk := newClock()
	root, err := moduleRoot()
	if err != nil {
		return err
	}
	h, err := dialHost(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	clk.mark("connect")

	facts, err := preflight(ctx, h, name)
	if err != nil {
		return err
	}
	if len(facts["base"]) == 0 || facts["base"][0] != "yes" {
		return fmt.Errorf("the base image %s is not on the lab host", lab.BaseImage)
	}
	iface := ifaceOf(facts["addr"], h.cfg.ExternalIP)
	if iface == "" {
		return fmt.Errorf("%s is not on an interface of the lab host", h.cfg.ExternalIP)
	}
	exists, mine, used := existing(facts, name)
	kevasod := ""
	if len(facts["kevasod"]) > 0 {
		kevasod = facts["kevasod"][0]
	}
	if err := lab.RefuseUp(name, exists, *recreate, lab.KevasodActive(kevasod), len(facts["lab"])); err != nil {
		return err
	}
	clk.mark("check")

	if exists && *recreate {
		script, err := lab.DestroyScript(name)
		if err != nil {
			return err
		}
		if _, err := h.run(ctx, script); err != nil {
			return fmt.Errorf("removing the existing lab: %w", err)
		}
		if err := os.RemoveAll(labDir(root, name)); err != nil {
			return err
		}
		clk.mark("recreate")
	}

	slot := mine
	if slot < 1 || slot > lab.MaxLabs {
		slot, err = lab.AllocateSlot(used)
		if err != nil {
			return err
		}
	}
	if _, err := h.run(ctx, claimScript(name, slot)); err != nil {
		return fmt.Errorf("claiming slot %d: %w", slot, err)
	}
	if *pair {
		if _, err := h.run(ctx, "printf '%s\\n' pair > "+sshboot.Quote(lab.StateDir(name)+"/mode")); err != nil {
			return fmt.Errorf("recording pair mode: %w", err)
		}
	}
	ports, err := lab.PortsFor(slot)
	if err != nil {
		return err
	}
	clk.mark("slot")

	local := labDir(root, name)
	if err := os.MkdirAll(local, 0o700); err != nil {
		return err
	}
	keyPath := filepath.Join(local, "id_ed25519")
	pub, err := installKey(ctx, h, name, keyPath)
	if err != nil {
		return err
	}
	clk.mark("key")

	// The binaries build while the VMs boot.
	bctx, bcancel := context.WithCancel(ctx)
	defer bcancel()
	buildDone := make(chan error, 1)
	if !*pair {
		go func() { buildDone <- buildBins(bctx, root, filepath.Join(local, "bin")) }()
	}

	if err := bringUp(ctx, h, name, slot, iface, pub, nodes, *pair); err != nil {
		bcancel()
		return err
	}
	clk.mark("define")

	pins := map[string]string{}
	type pinned struct {
		role, pin string
		err       error
	}
	pc := make(chan pinned, len(nodes))
	for _, n := range nodes {
		go func(n lab.Node) {
			addr := net.JoinHostPort(h.cfg.ExternalIP, strconv.Itoa(ports.SSH(n.Role)))
			pin, err := waitNode(ctx, addr, keyPath)
			if err != nil {
				err = fmt.Errorf("%s (%s): %w", n.Role, addr, err)
			}
			pc <- pinned{n.Role, pin, err}
		}(n)
	}
	var waitErrs []error
	for range nodes {
		p := <-pc
		if p.err != nil {
			waitErrs = append(waitErrs, p.err)
			continue
		}
		pins[p.role] = p.pin
	}
	if len(waitErrs) > 0 {
		bcancel()
		diag, _ := h.run(ctx, diagScript(name, slot, nodes))
		return fmt.Errorf("%s\n%s", errors.Join(waitErrs...), scrub(diag))
	}
	clk.mark("boot")

	envPath := filepath.Join(local, "env.sh")
	var text string
	if *pair {
		// The tests reset each machine against the harness baseline and install Kevaso
		// themselves. Record that baseline now, on the fresh VM, the same way a real
		// machine had it recorded (remote.RecordBaseline).
		if err := recordBaselines(ctx, h.cfg.ExternalIP, slot, nodes, ports, pins, keyPath); err != nil {
			return err
		}
		clk.mark("baseline")
		hostPorts, hpErr := ports.HostPorts()
		if hpErr != nil {
			return hpErr
		}
		text, err = lab.PairEnvFile(lab.PairEnv{
			Name: name, Host: "ubuntu@" + h.cfg.ExternalIP,
			M1SSH: ports.SSH("m1"), M2SSH: ports.SSH("m2"), KeyPath: keyPath,
			M1HostKey: pins["m1"], M2HostKey: pins["m2"], ExternalIP: h.cfg.ExternalIP,
			M1Internal: lab.IP(slot, 10), M2Internal: lab.IP(slot, 11), SpareDisk: lab.SpareByID,
			APIPort: ports.API, HostPorts: hostPorts,
		})
	} else {
		seedPath := lab.StateDir(name) + "/seed.sh"
		if err := h.upload(ctx, seedPath, []byte(seedScript(name, slot)), 0o700); err != nil {
			return fmt.Errorf("seed script: %w", err)
		}
		if out, err := h.run(ctx, "bash "+sshboot.Quote(seedPath)); err != nil {
			fmt.Printf("seed: the download cache was not copied (%s); the workers will fetch it\n", scrub(err.Error()))
		} else if strings.Contains(out, "seeded") {
			fmt.Println("seed: cloud-hypervisor and the Ubuntu image are on the workers")
		}
		clk.mark("seed")

		if err := <-buildDone; err != nil {
			return err
		}
		clk.mark("build")

		bin := filepath.Join(local, "bin")
		if err := installKevaso(ctx, h, name, slot, ports, pins, keyPath, filepath.Join(bin, "kevasod"), filepath.Join(bin, "kvoadm"), local); err != nil {
			return err
		}
		clk.mark("kevaso")

		if err := waitRuntimes(ctx, filepath.Join(bin, "kvo"), local); err != nil {
			return err
		}
		clk.mark("runtimes")

		text, err = lab.EnvFile(lab.Env{
			Name: name, Host: "ubuntu@" + h.cfg.ExternalIP, SSHPort: ports.SysSSH,
			KeyPath: keyPath, HostKey: pins["sys"], ExternalIP: h.cfg.ExternalIP,
			InternalIP: lab.IP(slot, 10), ConfigPath: filepath.Join(local, "config.yaml"),
		})
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(envPath, []byte(text), 0o644); err != nil {
		return err
	}
	timing := clk.done()
	_ = os.WriteFile(filepath.Join(local, "timings.txt"), []byte(timing), 0o644)
	if *pair {
		fmt.Printf("\nlab %s is up (slot %d, %s, pair)\n", name, slot, lab.CIDR(slot))
		fmt.Printf("  m1   ssh %s:%d   %s\n", h.cfg.ExternalIP, ports.SSH("m1"), lab.IP(slot, 10))
		fmt.Printf("  m2   ssh %s:%d   %s   spare %s\n", h.cfg.ExternalIP, ports.SSH("m2"), lab.IP(slot, 11), lab.SpareByID)
		fmt.Printf("  api  https://%s\n", net.JoinHostPort(h.cfg.ExternalIP, strconv.Itoa(ports.API)))
	} else {
		fmt.Printf("\nlab %s is up (slot %d, %s)\n", name, slot, lab.CIDR(slot))
		fmt.Printf("  sys  ssh %s:%d   %s\n", h.cfg.ExternalIP, ports.SysSSH, lab.IP(slot, 10))
		fmt.Printf("  w1   ssh %s:%d   %s\n", h.cfg.ExternalIP, ports.W1SSH, lab.IP(slot, 11))
		fmt.Printf("  w2   ssh %s:%d   %s\n", h.cfg.ExternalIP, ports.W2SSH, lab.IP(slot, 12))
		fmt.Printf("  api  https://%s\n", net.JoinHostPort(h.cfg.ExternalIP, strconv.Itoa(ports.API)))
	}
	fmt.Printf("  env  %s\n", envPath)
	fmt.Print(timing)
	return nil
}

func preflight(ctx context.Context, h *labHost, name string) (map[string][]string, error) {
	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("echo \"kevasod=$(systemctl is-active kevasod 2>/dev/null || true)\"\n")
	fmt.Fprintf(&b, "if [ -f %s ]; then echo base=yes; else echo base=no; fi\n", sshboot.Quote(lab.BaseImage))
	b.WriteString("ip -4 -o addr show | awk '{print \"addr=\" $2 \" \" $4}'\n")
	b.WriteString("if [ -d /root/kvl ]; then\n")
	b.WriteString("  for d in /root/kvl/*/; do\n")
	b.WriteString("    [ -f \"${d}slot\" ] || continue\n")
	b.WriteString("    name=$(basename \"$d\")\n")
	b.WriteString("    slot=$(tr -d '[:space:]' < \"${d}slot\")\n")
	b.WriteString("    echo \"lab=$name $slot\"\n")
	b.WriteString("  done\nfi\n")
	for _, n := range lab.AllNodes() {
		fmt.Fprintf(&b, "virsh dominfo %s >/dev/null 2>&1 && echo have=domain || true\n", sshboot.Quote(lab.VMName(name, n.Role)))
	}
	fmt.Fprintf(&b, "virsh net-info %s >/dev/null 2>&1 && echo have=network || true\n", sshboot.Quote(lab.NetworkName(name)))
	fmt.Fprintf(&b, "[ -d %s ] && echo have=dir || true\n", sshboot.Quote(lab.StateDir(name)))
	out, err := h.run(ctx, b.String())
	if err != nil {
		return nil, fmt.Errorf("reading the lab host: %w", err)
	}
	return parseFacts(out), nil
}

// existing says whether this name is already a lab, which slot it held, and the slots the
// other labs hold.
func existing(facts map[string][]string, name string) (exists bool, slot int, used []int) {
	for _, line := range facts["lab"] {
		n, slotS, ok := cut2(line)
		if !ok {
			continue
		}
		s, _ := strconv.Atoi(slotS)
		if n == name {
			exists = true
			slot = s
			continue
		}
		if s > 0 {
			used = append(used, s)
		}
	}
	if len(facts["have"]) > 0 {
		exists = true
	}
	return exists, slot, used
}

func ifaceOf(addrs []string, ip string) string {
	for _, line := range addrs {
		dev, cidr, ok := cut2(line)
		if ok && strings.HasPrefix(cidr, ip+"/") {
			return dev
		}
	}
	return ""
}

func claimScript(name string, slot int) string {
	dir := sshboot.Quote(lab.StateDir(name))
	return fmt.Sprintf(`set -eu
mkdir -p /root/kvl
chmod 700 /root/kvl
exec 9>/root/kvl/.lock
flock -w 60 9
if [ -e %s ]; then echo 'lab directory appeared while the lock was waited for' >&2; exit 1; fi
for d in /root/kvl/*/; do
  [ -f "${d}slot" ] || continue
  s=$(tr -d '[:space:]' < "${d}slot")
  [ "$s" = %d ] && { echo "slot %d is already used" >&2; exit 1; }
done
mkdir -p %s
chmod 700 %s
echo %d > %s/slot
echo claimed
`, dir, slot, slot, dir, dir, slot, dir)
}

// installKey makes the lab's key on the host (never printed) and copies it into keyPath.
// The public line is what cloud-init installs.
func installKey(ctx context.Context, h *labHost, name, keyPath string) (string, error) {
	dir := lab.StateDir(name)
	priv, pub := dir+"/id_ed25519", dir+"/id_ed25519.pub"
	script := fmt.Sprintf(`set -eu
if [ ! -f %s ]; then ssh-keygen -q -t ed25519 -N '' -C %s -f %s; fi
chmod 600 %s
chmod 644 %s
`, sshboot.Quote(priv), sshboot.Quote("kvl-"+name), sshboot.Quote(priv), sshboot.Quote(priv), sshboot.Quote(pub))
	if _, err := h.run(ctx, script); err != nil {
		return "", fmt.Errorf("lab ssh key: %w", err)
	}
	// The error from a failed read must not include the file.
	out, err := h.d.Run(ctx, "cat "+sshboot.Quote(priv), nil)
	if err != nil || !strings.Contains(out, "OPENSSH PRIVATE KEY") {
		return "", errors.New("could not read the lab key from the host")
	}
	if err := os.WriteFile(keyPath, []byte(out), 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return "", err
	}
	pubOut, err := h.d.Run(ctx, "cat "+sshboot.Quote(pub), nil)
	if err != nil {
		return "", errors.New("could not read the lab public key from the host")
	}
	line := strings.TrimSpace(pubOut)
	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		return "", errors.New("the lab public key is not ed25519")
	}
	return line, nil
}

func bringUp(ctx context.Context, h *labHost, name string, slot int, iface, pub string, nodes []lab.Node, pair bool) error {
	dir := lab.StateDir(name)
	if err := h.upload(ctx, dir+"/user-data", []byte(lab.UserData(pub)), 0o600); err != nil {
		return fmt.Errorf("user-data: %w", err)
	}
	xml, err := lab.NetworkXML(name, slot, true)
	if pair {
		xml, err = lab.PairNetworkXML(name, slot, true)
	}
	if err != nil {
		return err
	}
	netPath := dir + "/network.xml"
	if err := h.upload(ctx, netPath, []byte(xml), 0o644); err != nil {
		return err
	}
	net := lab.NetworkName(name)
	define := fmt.Sprintf("virsh net-define %s && virsh net-start %s", sshboot.Quote(netPath), sshboot.Quote(net))
	if _, err := h.run(ctx, define); err != nil {
		plain, perr := lab.NetworkXML(name, slot, false)
		if pair {
			plain, perr = lab.PairNetworkXML(name, slot, false)
		}
		if perr != nil {
			return err
		}
		if uerr := h.upload(ctx, netPath, []byte(plain), 0o644); uerr != nil {
			return uerr
		}
		if _, err2 := h.run(ctx, define); err2 != nil {
			return fmt.Errorf("libvirt network: %w", err2)
		}
		if pair {
			fmt.Println("note: this libvirt rejected the wildcard DNS entry; m1/m2 names are still served")
		} else {
			fmt.Println("note: this libvirt rejected the wildcard DNS entry; sys/w1/w2 names are still served")
		}
	}
	for _, n := range nodes {
		if err := h.upload(ctx, dir+"/meta-"+n.Role, []byte(lab.MetaData(name, n.Role)), 0o644); err != nil {
			return err
		}
		dom, err := lab.DomainXML(name, slot, n)
		if err != nil {
			return err
		}
		if err := h.upload(ctx, dir+"/"+lab.VMName(name, n.Role)+".xml", []byte(dom), 0o644); err != nil {
			return err
		}
	}
	if _, err := h.run(ctx, diskScript(name, nodes)); err != nil {
		return fmt.Errorf("disks: %w", err)
	}
	fw, err := lab.ForwardScript(name, slot, iface)
	if pair {
		fw, err = lab.PairForwardScript(name, slot, iface, h.cfg.ExternalIP)
	}
	if err != nil {
		return err
	}
	if _, err := h.run(ctx, fw); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	if _, err := h.run(ctx, startScript(name, nodes)); err != nil {
		return fmt.Errorf("virsh start: %w", err)
	}
	return nil
}

func diskScript(name string, nodes []lab.Node) string {
	dir := lab.StateDir(name)
	var b strings.Builder
	b.WriteString("set -eu\n")
	for _, n := range nodes {
		disk, seed := lab.Disk(name, n.Role), lab.Seed(name, n.Role)
		fmt.Fprintf(&b, "qemu-img create -f qcow2 -F qcow2 -b %s %s %dG\n",
			sshboot.Quote(lab.BaseImage), sshboot.Quote(disk), n.DiskGiB)
		fmt.Fprintf(&b, "chown libvirt-qemu:kvm %s && chmod 660 %s\n", sshboot.Quote(disk), sshboot.Quote(disk))
		if n.SpareSerial != "" {
			spare := lab.SpareDisk(name)
			fmt.Fprintf(&b, "qemu-img create -f qcow2 %s %dG\n", sshboot.Quote(spare), lab.SpareDiskGiB)
			fmt.Fprintf(&b, "chown libvirt-qemu:kvm %s && chmod 660 %s\n", sshboot.Quote(spare), sshboot.Quote(spare))
		}
		fmt.Fprintf(&b, "cloud-localds %s %s %s\n", sshboot.Quote(seed), sshboot.Quote(dir+"/user-data"), sshboot.Quote(dir+"/meta-"+n.Role))
		fmt.Fprintf(&b, "chown libvirt-qemu:kvm %s && chmod 644 %s\n", sshboot.Quote(seed), sshboot.Quote(seed))
		fmt.Fprintf(&b, "virsh define %s\n", sshboot.Quote(dir+"/"+lab.VMName(name, n.Role)+".xml"))
	}
	return b.String()
}

func startScript(name string, nodes []lab.Node) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	for _, n := range nodes {
		fmt.Fprintf(&b, "virsh start %s\n", sshboot.Quote(lab.VMName(name, n.Role)))
	}
	return b.String()
}

func diagScript(name string, slot int, nodes []lab.Node) string {
	var b strings.Builder
	b.WriteString("set +e\n")
	b.WriteString("virsh list --all\nvirsh net-list --all\n")
	fmt.Fprintf(&b, "ip -br addr show %s\n", lab.Bridge(slot))
	b.WriteString("nft list table inet kvl\n")
	for _, n := range nodes {
		vm := lab.VMName(name, n.Role)
		fmt.Fprintf(&b, "echo -- %s --\nvirsh domifaddr %s --source lease\n", n.Role, sshboot.Quote(vm))
		fmt.Fprintf(&b, "echo -- serial %s --\ntail -n 20 /var/log/libvirt/qemu/%s-serial.log\n", n.Role, vm)
		fmt.Fprintf(&b, "ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 -i %s ubuntu@%s echo HOST_SSH_OK || echo HOST_SSH_FAIL %s\n",
			sshboot.Quote(lab.StateDir(name)+"/known_hosts"), sshboot.Quote(lab.StateDir(name)+"/id_ed25519"), lab.IP(slot, n.Octet), n.Role)
	}
	return b.String()
}

// recordBaselines runs remote.RecordBaseline on each fresh VM: the checklist must pass, then
// the machine's packages, nftables tables and IP forwarding are written to
// /var/lib/kvt-baseline/state. That is the baseline the metal tests reset against.
func recordBaselines(ctx context.Context, host string, slot int, nodes []lab.Node, ports lab.Ports, pins map[string]string, keyPath string) error {
	errc := make(chan error, len(nodes))
	for _, n := range nodes {
		go func(n lab.Node) {
			errc <- recordBaseline(ctx, host, slot, n, ports, pins[n.Role], keyPath)
		}(n)
	}
	var errs []error
	for range nodes {
		if err := <-errc; err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	fmt.Println("baseline: recorded on each machine (/var/lib/kvt-baseline)")
	return nil
}

func recordBaseline(ctx context.Context, host string, slot int, n lab.Node, ports lab.Ports, pin, keyPath string) error {
	cfg := remote.Config{
		User: "ubuntu", Address: host, Port: ports.SSH(n.Role), KeyFile: keyPath, HostKey: pin,
		ExternalIP: host, InternalIP: lab.IP(slot, n.Octet),
	}
	if n.SpareSerial != "" {
		cfg.SpareDisk = lab.SpareByID
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("%s: %w", n.Role, err)
	}
	d := remote.New(cfg)
	defer func() { _ = d.Close() }()
	if n.SpareSerial != "" {
		byID := sshboot.Quote(lab.SpareByID)
		script := "for i in $(seq 1 15); do if [ -b " + byID + " ]; then lsblk -dn -o TYPE,SIZE " + byID + "; exit 0; fi; sleep 1; done; echo MISSING; ls -1 /dev/disk/by-id 2>/dev/null || true; exit 1"
		out, err := d.Run(ctx, script, nil)
		if err != nil {
			return fmt.Errorf("%s: spare disk %s: %v\n%s", n.Role, lab.SpareByID, err, scrub(out))
		}
	}
	if _, err := d.RecordBaseline(ctx); err != nil {
		return fmt.Errorf("%s: recording the harness baseline: %w", n.Role, err)
	}
	return nil
}

func seedScript(name string, slot int) string {
	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	b.WriteString("[ -f /var/cache/kvt/ch/cloud-hypervisor ] && [ -f /var/cache/kvt/images/ubuntu-24.04-x86_64.img ] || { echo noseed; exit 0; }\n")
	key := sshboot.Quote(lab.StateDir(name) + "/id_ed25519")
	kh := sshboot.Quote(lab.StateDir(name) + "/known_hosts")
	for _, n := range lab.Nodes() {
		if n.Role == "sys" {
			continue
		}
		ip := lab.IP(slot, n.Octet)
		fmt.Fprintf(&b, "ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s -o IdentitiesOnly=yes -o BatchMode=yes -i %s ubuntu@%s 'sudo -n install -d -m 0755 /opt/kevaso/cloud-hypervisor && sudo -n install -d -m 0700 /var/lib/kevaso-images'\n", kh, key, ip)
		fmt.Fprintf(&b, "tar -C /var/cache/kvt/ch -cf - cloud-hypervisor ch-remote CLOUDHV.fd | ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s -o IdentitiesOnly=yes -o BatchMode=yes -i %s ubuntu@%s 'sudo -n tar -C /opt/kevaso/cloud-hypervisor -xf - && sudo -n chmod 755 /opt/kevaso/cloud-hypervisor/cloud-hypervisor /opt/kevaso/cloud-hypervisor/ch-remote /opt/kevaso/cloud-hypervisor/CLOUDHV.fd'\n", kh, key, ip)
		fmt.Fprintf(&b, "tar -C /var/cache/kvt/images -cf - ubuntu-24.04-x86_64.img | ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s -o IdentitiesOnly=yes -o BatchMode=yes -i %s ubuntu@%s 'sudo -n tar -C /var/lib/kevaso-images -xf - && sudo -n chmod 600 /var/lib/kevaso-images/ubuntu-24.04-x86_64.img'\n", kh, key, ip)
	}
	b.WriteString("echo seeded\n")
	return b.String()
}

func waitNode(ctx context.Context, addr, keyPath string) (string, error) {
	deadline := time.Now().Add(5 * time.Minute)
	var pin string
	var last error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if pin == "" {
			pin, last = probeHostKey(addr)
			if pin == "" {
				sleep(ctx, time.Second)
				continue
			}
		}
		cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		out, err := vmRun(cctx, addr, keyPath, pin, "sudo -n cloud-init status --wait; echo CLOUD_INIT_OK; if test -c /dev/kvm; then echo kvm=yes; else echo kvm=no; fi")
		cancel()
		if err == nil && strings.Contains(out, "CLOUD_INIT_OK") {
			if !strings.Contains(out, "kvm=yes") {
				return pin, fmt.Errorf("%s has no /dev/kvm", addr)
			}
			return pin, nil
		}
		last = err
		sleep(ctx, 2*time.Second)
	}
	if last == nil {
		last = errors.New("no ssh")
	}
	return pin, fmt.Errorf("timed out: %v", last)
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func buildBins(ctx context.Context, root, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	type one struct {
		name string
		env  []string
	}
	base := cleanEnv("GOPROXY=off", "CGO_ENABLED=0")
	linux := append(append([]string{}, base...), "GOOS=linux", "GOARCH=amd64")
	for _, b := range []one{
		{"kevasod", linux},
		{"kvoadm", base},
		{"kvo", base},
	} {
		cmd := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(dir, b.name), "kevaso.com/core/cmd/"+b.name)
		cmd.Dir = root
		cmd.Env = b.env
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("build %s: %w\n%s", b.name, err, out)
		}
	}
	return nil
}

func cleanEnv(extra ...string) []string {
	drop := map[string]bool{"GOOS": true, "GOARCH": true, "CGO_ENABLED": true, "GOPROXY": true}
	var out []string
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		if !drop[k] {
			out = append(out, e)
		}
	}
	return append(out, extra...)
}

func childEnv(labDir, config string) []string {
	drop := map[string]bool{"HOME": true, "KVO_CONFIG": true, "KVO_SERVER": true, "KVO_TOKEN_STORE": true}
	var out []string
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		if !drop[k] {
			out = append(out, e)
		}
	}
	return append(out, "HOME="+labDir, "KVO_CONFIG="+config, "KVO_TOKEN_STORE=file")
}

func installKevaso(ctx context.Context, h *labHost, name string, slot int, ports lab.Ports, pins map[string]string, keyPath, kevasod, kvoadm, local string) error {
	var printMu sync.Mutex
	run := func(args ...string) error {
		cmd := exec.CommandContext(ctx, kvoadm, args...)
		cmd.Env = childEnv(local, filepath.Join(local, "config.yaml"))
		cmd.Dir = local
		var buf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &buf, &buf
		err := cmd.Run()
		text := buf.String()
		if k := recoveryKey.FindString(text); k != "" {
			_ = os.WriteFile(filepath.Join(local, "recovery-key"), []byte(k+"\n"), 0o600)
		}
		printMu.Lock()
		fmt.Print(scrub(text))
		printMu.Unlock()
		if err != nil {
			return fmt.Errorf("kvoadm %s: %w", args[0], err)
		}
		return nil
	}
	api := "https://" + net.JoinHostPort(h.cfg.ExternalIP, strconv.Itoa(ports.API))
	if err := run("init", "ubuntu@"+h.cfg.ExternalIP,
		"--ssh-port", strconv.Itoa(ports.SysSSH), "--ssh-key", keyPath, "--host-key", pins["sys"],
		"--kevasod", kevasod, "--name", "sys", "--cluster", name, "--api-server", api,
		"--internal-ip", lab.IP(slot, 10), "--no-extra-hardening"); err != nil {
		return err
	}
	errc := make(chan error, 2)
	for _, n := range lab.Nodes() {
		if n.Role == "sys" {
			continue
		}
		n := n
		go func() {
			errc <- run("host", "add", "ubuntu@"+h.cfg.ExternalIP,
				"--ssh-port", strconv.Itoa(ports.SSH(n.Role)), "--ssh-key", keyPath, "--host-key", pins[n.Role],
				"--kevasod", kevasod, "--name", n.Role, "--install", "worker",
				"--runtime", "cloud-hypervisor", "--runtime", "docker",
				"--internal-ip", lab.IP(slot, n.Octet),
				"--server", "https://"+net.JoinHostPort(lab.IP(slot, 10), "6443"),
				"--loop-storage", "20G", "--no-extra-hardening")
		}()
	}
	var errs []error
	for range 2 {
		if err := <-errc; err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

var recoveryKey = regexp.MustCompile(`KVR1-[A-Z0-9-]+`)

func waitRuntimes(ctx context.Context, kvoBin, local string) error {
	deadline := time.Now().Add(15 * time.Minute)
	var last string
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		ready := 0
		var lines []string
		for _, role := range []string{"w1", "w2"} {
			out, err := kvoCmd(ctx, kvoBin, local, "get", "host", role, "-o", "json")
			if err != nil {
				lines = append(lines, role+" "+scrub(err.Error()))
				continue
			}
			st, msg, failed := runtimeState(out)
			if failed != "" {
				return fmt.Errorf("%s runtime failed: %s", role, failed)
			}
			lines = append(lines, role+" "+st+" "+msg)
			if st == "ready" {
				ready++
			}
		}
		last = strings.Join(lines, "; ")
		if ready == 2 {
			return nil
		}
		fmt.Printf("runtimes: %s\n", last)
		sleep(ctx, 10*time.Second)
	}
	return fmt.Errorf("runtimes not Ready: %s", last)
}

func kvoCmd(ctx context.Context, bin, local string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = childEnv(local, filepath.Join(local, "config.yaml"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// runtimeState reads one host's JSON. It returns "ready" when both runtimes and the host are Ready.
func runtimeState(out string) (state, msg, failed string) {
	var h struct {
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
			Runtimes map[string]struct {
				State   string `json:"state"`
				Message string `json:"message"`
			} `json:"runtimes"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &h); err != nil {
		return "bad-json", "", ""
	}
	hostReady := false
	for _, c := range h.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" {
			hostReady = true
		}
	}
	for _, rt := range []string{"cloud-hypervisor", "docker"} {
		st, ok := h.Status.Runtimes[rt]
		if !ok {
			return "waiting", rt + " not reported", ""
		}
		switch st.State {
		case "Failed":
			return "failed", "", rt + ": " + st.Message
		case "Ready":
		default:
			return "installing", rt + "=" + st.State + " " + st.Message, ""
		}
	}
	if !hostReady {
		return "host-not-ready", "", ""
	}
	return "ready", "", ""
}

type clock struct {
	t0, last time.Time
	rows     []string
}

func newClock() *clock {
	n := time.Now()
	return &clock{t0: n, last: n}
}

func (c *clock) mark(name string) {
	d := time.Since(c.last)
	c.rows = append(c.rows, fmt.Sprintf("%-16s %s", name, d.Round(time.Millisecond)))
	fmt.Printf("stage %-16s %s\n", name, d.Round(time.Millisecond))
	c.last = time.Now()
}

func (c *clock) done() string {
	var b strings.Builder
	b.WriteString("timings:\n")
	for _, r := range c.rows {
		b.WriteString("  " + r + "\n")
	}
	fmt.Fprintf(&b, "  %-16s %s\n", "total", time.Since(c.t0).Round(time.Millisecond))
	return b.String()
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && bytes.Contains(b, []byte("module kevaso.com/core\n")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("kvlab must be run from the kevaso.com/core worktree")
		}
		dir = parent
	}
}
