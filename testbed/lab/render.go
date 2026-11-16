package lab

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// serialRE is a virtio-blk serial: short, and safe to place in the domain XML.
var serialRE = regexp.MustCompile(`^[a-z0-9]{1,20}$`)

// UserData is the cloud-init NoCloud user-data for every node of a lab. pub is one OpenSSH
// public-key line. The login is ubuntu, with passwordless sudo, and the account is locked to
// that key.
func UserData(pub string) string {
	return `#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [kvm]
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - ` + strconv.Quote(strings.TrimSpace(pub)) + `
ssh_pwauth: false
disable_root: true
package_update: false
package_upgrade: false
`
}

// MetaData is the cloud-init meta-data for one node. The instance id is the VM name, so a fresh
// overlay runs cloud-init from the start.
func MetaData(name, role string) string {
	vm := VMName(name, role)
	return "instance-id: " + vm + "\nlocal-hostname: " + vm + "\n"
}

// NetworkXML is the libvirt network for one lab. Forward mode is open, not nat: nat mode
// installs a rule that rejects new connections into the bridge, and that drops the ports this
// lab publishes on the host. Open mode adds no firewall rules. The guests' own traffic is
// masqueraded by ForwardScript, in Table. wildcard adds a dnsmasq address rule so any name
// under NAME.lab.test answers with the system node (ingress). The three node names are always
// there; the caller drops the wildcard and defines again when this libvirt rejects it.
func NetworkXML(name string, slot int, wildcard bool) (string, error) {
	return networkXML(name, slot, wildcard, Nodes())
}

// PairNetworkXML is the same network for a pair lab: m1 and m2, instead of sys, w1 and w2.
func PairNetworkXML(name string, slot int, wildcard bool) (string, error) {
	return networkXML(name, slot, wildcard, PairNodes())
}

func networkXML(name string, slot int, wildcard bool, nodes []Node) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	if _, err := PortsFor(slot); err != nil {
		return "", err
	}
	if len(nodes) == 0 {
		return "", fmt.Errorf("network %s: no nodes", name)
	}
	var hosts, dhcp strings.Builder
	lo, hi := nodes[0].Octet, nodes[0].Octet
	for _, n := range nodes {
		if n.Octet < lo {
			lo = n.Octet
		}
		if n.Octet > hi {
			hi = n.Octet
		}
		ip := IP(slot, n.Octet)
		fmt.Fprintf(&hosts, "    <host ip='%s'>\n      <hostname>%s</hostname>\n    </host>\n", ip, Hostname(name, n.Role))
		fmt.Fprintf(&dhcp, "        <host mac='%s' name='%s' ip='%s'/>\n", MAC(slot, n.Octet), n.Role, ip)
	}
	var extra string
	if wildcard {
		// The first node answers every other name under NAME.lab.test (ingress).
		extra = "  <dnsmasq:options>\n    <dnsmasq:option value='address=/." + name + "." + DNSDomain + "/" + IP(slot, nodes[0].Octet) + "'/>\n  </dnsmasq:options>\n"
	}
	return `<network xmlns:dnsmasq='http://libvirt.org/schemas/network/dnsmasq/1.0'>
  <name>` + NetworkName(name) + `</name>
  <forward mode='open'/>
  <bridge name='` + Bridge(slot) + `' stp='on' delay='0'/>
  <domain name='` + DNSDomain + `' localOnly='yes'/>
  <dns enable='yes'>
` + hosts.String() + `  </dns>
` + extra + `  <ip address='` + IP(slot, 1) + `' netmask='255.255.255.0'>
    <dhcp>
      <range start='` + IP(slot, lo) + `' end='` + IP(slot, hi) + `'/>
` + dhcp.String() + `    </dhcp>
  </ip>
</network>
`, nil
}

// DomainXML is one libvirt domain: a thin overlay of the base image, host-passthrough with
// migration off so the guest keeps svm, and a NoCloud seed on a SATA CD.
func DomainXML(name string, slot int, n Node) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	if _, err := PortsFor(slot); err != nil {
		return "", err
	}
	vm := VMName(name, n.Role)
	serialLog := "/var/log/libvirt/qemu/" + vm + "-serial.log"
	spare := ""
	if n.SpareSerial != "" {
		if !serialRE.MatchString(n.SpareSerial) {
			return "", fmt.Errorf("disk serial %q: want 1 to 20 letters or digits", n.SpareSerial)
		}
		// A second virtio disk, empty, with a stable serial. The guest's udev names it
		// /dev/disk/by-id/virtio-SERIAL. It is not an overlay of the base image.
		spare = `    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none' io='native' discard='unmap'/>
      <source file='` + SpareDisk(name) + `'/>
      <target dev='vdb' bus='virtio'/>
      <serial>` + n.SpareSerial + `</serial>
    </disk>
`
	}
	return `<domain type='kvm'>
  <name>` + vm + `</name>
  <memory unit='MiB'>` + strconv.Itoa(n.MemoryMiB) + `</memory>
  <currentMemory unit='MiB'>` + strconv.Itoa(n.MemoryMiB) + `</currentMemory>
  <vcpu placement='static'>` + strconv.Itoa(n.VCPU) + `</vcpu>
  <cpu mode='host-passthrough' check='none' migratable='off'/>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none' io='native' discard='unmap'/>
      <source file='` + Disk(name, n.Role) + `'/>
      <target dev='vda' bus='virtio'/>
    </disk>
` + spare + `    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='` + Seed(name, n.Role) + `'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <mac address='` + MAC(slot, n.Octet) + `'/>
      <source network='` + NetworkName(name) + `'/>
      <model type='virtio'/>
    </interface>
    <serial type='file'>
      <source path='` + serialLog + `'/>
      <target type='isa-serial' port='0'/>
    </serial>
    <memballoon model='virtio'/>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>
</domain>
`, nil
}

// ForwardScript is the nftables rules for one lab, in Table only. DNAT is on the host interface
// that holds the public address, at a priority just before the iptables dstnat hook. Connections
// that rule rewrote are masqueraded as they leave the lab bridge, so the guest answers the
// gateway. The guests' own traffic is masqueraded as it leaves the public interface, because the
// network is open and libvirt does not masquerade it.
func ForwardScript(name string, slot int, iface string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	if iface == "" || strings.ContainsAny(iface, " \t'\"$;|&") {
		return "", fmt.Errorf("interface %q: want a device name", iface)
	}
	p, err := PortsFor(slot)
	if err != nil {
		return "", err
	}
	pre, post := PreChain(name), PostChain(name)
	var b strings.Builder
	fmt.Fprintf(&b, "set -eu\n")
	fmt.Fprintf(&b, "nft list table %s >/dev/null 2>&1 || nft add table %s\n", Table, Table)
	fmt.Fprintf(&b, "nft flush chain %s %s >/dev/null 2>&1 || true\n", Table, q(pre))
	fmt.Fprintf(&b, "nft delete chain %s %s >/dev/null 2>&1 || true\n", Table, q(pre))
	fmt.Fprintf(&b, "nft flush chain %s %s >/dev/null 2>&1 || true\n", Table, q(post))
	fmt.Fprintf(&b, "nft delete chain %s %s >/dev/null 2>&1 || true\n", Table, q(post))
	fmt.Fprintf(&b, "nft add chain %s %s '{ type nat hook prerouting priority dstnat - 10; policy accept; }'\n", Table, q(pre))
	fmt.Fprintf(&b, "nft add chain %s %s '{ type nat hook postrouting priority srcnat; policy accept; }'\n", Table, q(post))
	for _, n := range Nodes() {
		fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 iifname %s tcp dport %d dnat ip to %s:22\n",
			Table, q(pre), q(iface), p.SSH(n.Role), IP(slot, n.Octet))
	}
	fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 iifname %s tcp dport %d dnat ip to %s:6443\n",
		Table, q(pre), q(iface), p.API, IP(slot, 10))
	fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 oifname %s ct status dnat masquerade\n",
		Table, q(post), q(Bridge(slot)))
	fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 ip saddr %s oifname %s masquerade\n",
		Table, q(post), CIDR(slot), q(iface))
	return b.String(), nil
}

// PairForwardScript publishes a pair lab. SSH uses the slot block, the same offsets as the
// system node and the first worker. The API uses that block too (Ports.API, guest 6443): the
// public interface and the lab bridge (hairpin), so the Mac and m2 both dial the external
// address on the slot port. The guest still listens on 6443. The bridge also hairpins 6443,
// because that is the URL the control plane advertises (its listen port) and kvoadm init
// --restore points workers at; it is not on the public interface, so two labs do not share
// one host port. Each port in PairDials is the same: the slot port on the public interface
// and the bridge, forwarded to the guest's own port. A slot port already taken on the host,
// or already forwarded by another lab, refuses the script. Public port 80 is the exception
// (Let's Encrypt HTTP-01, TestMetal2LongSoakSetup): it is published too, but only when the
// host does not already have it, and a second lab still starts.
func PairForwardScript(name string, slot int, iface, public string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	if iface == "" || strings.ContainsAny(iface, " \t'\"$;|&") {
		return "", fmt.Errorf("interface %q: want a device name", iface)
	}
	pub, err := publicIPv4(public)
	if err != nil {
		return "", err
	}
	p, err := PortsFor(slot)
	if err != nil {
		return "", err
	}
	hostPorts, err := p.HostPorts()
	if err != nil {
		return "", err
	}
	pre, post := PreChain(name), PostChain(name)
	var b strings.Builder
	fmt.Fprintf(&b, "set -eu\n")
	fmt.Fprintf(&b, "nft list table %s >/dev/null 2>&1 || nft add table %s\n", Table, Table)
	fmt.Fprintf(&b, "nft flush chain %s %s >/dev/null 2>&1 || true\n", Table, q(pre))
	fmt.Fprintf(&b, "nft delete chain %s %s >/dev/null 2>&1 || true\n", Table, q(pre))
	fmt.Fprintf(&b, "nft flush chain %s %s >/dev/null 2>&1 || true\n", Table, q(post))
	fmt.Fprintf(&b, "nft delete chain %s %s >/dev/null 2>&1 || true\n", Table, q(post))
	for _, d := range PairDials() {
		port := hostPorts[d.Port]
		fmt.Fprintf(&b, "if nft list table %s >/dev/null 2>&1 && nft list table %s | grep -q 'dport %d '; then echo 'port %d is already forwarded on the lab host' >&2; exit 1; fi\n",
			Table, Table, port, port)
		fmt.Fprintf(&b, "if ss -ltnH | awk '{print $4}' | grep -qE '[:.]%d$'; then echo 'port %d is in use on the lab host' >&2; exit 1; fi\n",
			port, port)
	}
	fmt.Fprintf(&b, "nft add chain %s %s '{ type nat hook prerouting priority dstnat - 10; policy accept; }'\n", Table, q(pre))
	fmt.Fprintf(&b, "nft add chain %s %s '{ type nat hook postrouting priority srcnat; policy accept; }'\n", Table, q(post))
	for _, n := range PairNodes() {
		fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 iifname %s tcp dport %d dnat ip to %s:22\n",
			Table, q(pre), q(iface), p.SSH(n.Role), IP(slot, n.Octet))
	}
	m1 := IP(slot, PairNodes()[0].Octet)
	// The slot's API port, on the public interface and from the lab bridge. The guest listens
	// on 6443; the Mac and m2 dial the external address on this port (KEVASO_METAL_API_PORT).
	fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 iifname %s tcp dport %d dnat ip to %s:6443\n",
		Table, q(pre), q(iface), p.API, m1)
	fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 iifname %s ip daddr %s tcp dport %d dnat ip to %s:6443\n",
		Table, q(pre), q(Bridge(slot)), pub, p.API, m1)
	// The control plane advertises https://<external>:6443 (the listen port). kvoadm has no
	// flag to change that, and init --restore points workers there. Hairpin it on this lab's
	// bridge only: a second lab's bridge is a different interface, and 6443 is not published
	// on the lab host's public address.
	fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 iifname %s ip daddr %s tcp dport 6443 dnat ip to %s:6443\n",
		Table, q(pre), q(Bridge(slot)), pub, m1)
	for _, d := range PairDials() {
		oct, err := pairOctet(d.Role)
		if err != nil {
			return "", err
		}
		ip := IP(slot, oct)
		host := hostPorts[d.Port]
		fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 iifname %s tcp dport %d dnat ip to %s:%d\n",
			Table, q(pre), q(iface), host, ip, d.Port)
		fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 iifname %s ip daddr %s tcp dport %d dnat ip to %s:%d\n",
			Table, q(pre), q(Bridge(slot)), pub, host, ip, d.Port)
	}
	// Let's Encrypt HTTP-01 connects to port 80 on the address the name resolves to. The slot
	// port cannot stand in for that. Take public 80 when it is free; a lab that finds it taken
	// still comes up, and TestMetal2LongSoakSetup runs on the lab that holds it.
	http, err := http01Dial()
	if err != nil {
		return "", err
	}
	httpOct, err := pairOctet(http.Role)
	if err != nil {
		return "", err
	}
	httpIP := IP(slot, httpOct)
	fmt.Fprintf(&b, "if nft list table %s >/dev/null 2>&1 && nft list table %s | grep -q 'dport %d '; then echo 'public port %d is already forwarded; this lab will not publish it, so TestMetal2LongSoakSetup runs one pair lab at a time' >&2\n",
		Table, Table, http.Port, http.Port)
	fmt.Fprintf(&b, "elif ss -ltnH | awk '{print $4}' | grep -qE '[:.]%d$'; then echo 'public port %d is in use on the lab host; this lab will not publish it, so TestMetal2LongSoakSetup runs one pair lab at a time' >&2\n",
		http.Port, http.Port)
	fmt.Fprintf(&b, "else\n")
	fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 iifname %s tcp dport %d dnat ip to %s:%d\n",
		Table, q(pre), q(iface), http.Port, httpIP, http.Port)
	fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 iifname %s ip daddr %s tcp dport %d dnat ip to %s:%d\n",
		Table, q(pre), q(Bridge(slot)), pub, http.Port, httpIP, http.Port)
	fmt.Fprintf(&b, "fi\n")
	fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 oifname %s ct status dnat masquerade\n",
		Table, q(post), q(Bridge(slot)))
	fmt.Fprintf(&b, "nft add rule %s %s meta nfproto ipv4 ip saddr %s oifname %s masquerade\n",
		Table, q(post), CIDR(slot), q(iface))
	return b.String(), nil
}

// http01Dial is the guest port Let's Encrypt's HTTP-01 challenge dials. It is also in
// PairDials, at a slot offset, for the Mac.
func http01Dial() (PairDial, error) {
	for _, d := range PairDials() {
		if d.Port == 80 {
			return d, nil
		}
	}
	return PairDial{}, fmt.Errorf("pair dials: port 80 is not published")
}

func pairOctet(role string) (int, error) {
	for _, n := range PairNodes() {
		if n.Role == role {
			return n.Octet, nil
		}
	}
	return 0, fmt.Errorf("pair dial role %q is not m1 or m2", role)
}

func publicIPv4(s string) (string, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return "", fmt.Errorf("public address %q: want a public IPv4 address", s)
	}
	return a.String(), nil
}

// DestroyScript removes one lab and nothing else: its domains (a node lab's three, or a pair
// lab's two; the names it does not have are a no-op), the one network, disks and logs prefixed
// kvl-NAME-, /root/kvl/NAME, and that lab's nftables chains. The table goes only when no chain
// is left. A lab that is already gone makes every step a no-op.
func DestroyScript(name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	net := NetworkName(name)
	pre, post := PreChain(name), PostChain(name)
	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("need=0\n")
	for _, n := range AllNodes() {
		fmt.Fprintf(&b, "virsh dominfo %s >/dev/null 2>&1 && need=1 || true\n", q(VMName(name, n.Role)))
	}
	fmt.Fprintf(&b, "virsh net-info %s >/dev/null 2>&1 && need=1 || true\n", q(net))
	fmt.Fprintf(&b, "[ -d %s ] && need=1 || true\n", q(StateDir(name)))
	fmt.Fprintf(&b, "ls %s/%s-* >/dev/null 2>&1 && need=1 || true\n", ImageDir, "kvl-"+name)
	fmt.Fprintf(&b, "nft list chain %s %s >/dev/null 2>&1 && need=1 || true\n", Table, q(pre))
	b.WriteString("[ \"$need\" = 1 ] || exit 0\n")
	b.WriteString("mkdir -p " + StateRoot + "\n")
	b.WriteString("exec 9>" + StateRoot + "/.lock\nflock 9\n")
	for _, n := range AllNodes() {
		vm := VMName(name, n.Role)
		fmt.Fprintf(&b, "virsh destroy %s >/dev/null 2>&1 || true\n", q(vm))
		fmt.Fprintf(&b, "virsh undefine %s --nvram >/dev/null 2>&1 || true\n", q(vm))
		fmt.Fprintf(&b, "virsh undefine %s >/dev/null 2>&1 || true\n", q(vm))
	}
	fmt.Fprintf(&b, "virsh net-destroy %s >/dev/null 2>&1 || true\n", q(net))
	fmt.Fprintf(&b, "virsh net-undefine %s >/dev/null 2>&1 || true\n", q(net))
	fmt.Fprintf(&b, "rm -f %s/%s-*\n", ImageDir, "kvl-"+name)
	fmt.Fprintf(&b, "rm -f /var/log/libvirt/qemu/%s-*\n", "kvl-"+name)
	fmt.Fprintf(&b, "rm -f /var/lib/libvirt/dnsmasq/%s.*\n", net)
	fmt.Fprintf(&b, "rm -rf %s\n", q(StateDir(name)))
	fmt.Fprintf(&b, "if nft list table %s >/dev/null 2>&1; then\n", Table)
	fmt.Fprintf(&b, "  nft flush chain %s %s >/dev/null 2>&1 || true\n", Table, q(pre))
	fmt.Fprintf(&b, "  nft delete chain %s %s >/dev/null 2>&1 || true\n", Table, q(pre))
	fmt.Fprintf(&b, "  nft flush chain %s %s >/dev/null 2>&1 || true\n", Table, q(post))
	fmt.Fprintf(&b, "  nft delete chain %s %s >/dev/null 2>&1 || true\n", Table, q(post))
	fmt.Fprintf(&b, "  if ! nft list table %s | grep -q '^[[:space:]]*chain '; then nft delete table %s; fi\n", Table, Table)
	b.WriteString("fi\n")
	return b.String(), nil
}

// Env is the file the metal tests source. The variable names are the ones test/e2e reads
// (KEVASO_METAL_*), plus LAB_NAME. KVO_CONFIG points at the context kvoadm wrote, so kvo talks
// to this lab.
type Env struct {
	Name       string
	Host       string // ubuntu@public-ip
	SSHPort    int
	KeyPath    string
	HostKey    string // SHA256:… of the system node
	ExternalIP string
	InternalIP string
	ConfigPath string
}

// EnvFile renders Env as a shell script.
func EnvFile(e Env) (string, error) {
	if err := ValidName(e.Name); err != nil {
		return "", err
	}
	if e.SSHPort < 1 || e.Host == "" || e.KeyPath == "" || e.HostKey == "" || e.ExternalIP == "" || e.InternalIP == "" || e.ConfigPath == "" {
		return "", fmt.Errorf("env for %s: incomplete", e.Name)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# lab %s. source this file, then kvo and the metal tests talk to it.\n", e.Name)
	fmt.Fprintf(&b, "export LAB_NAME=%s\n", q(e.Name))
	fmt.Fprintf(&b, "export KEVASO_METAL_HOST=%s\n", q(e.Host+":"+strconv.Itoa(e.SSHPort)))
	fmt.Fprintf(&b, "export KEVASO_METAL_KEY=%s\n", q(e.KeyPath))
	fmt.Fprintf(&b, "export KEVASO_METAL_HOSTKEY=%s\n", q(e.HostKey))
	fmt.Fprintf(&b, "export KEVASO_METAL_EXTERNAL_IP=%s\n", q(e.ExternalIP))
	fmt.Fprintf(&b, "export KEVASO_METAL_INTERNAL_IP=%s\n", q(e.InternalIP))
	fmt.Fprintf(&b, "export KVO_CONFIG=%s\n", q(e.ConfigPath))
	b.WriteString("export KVO_TOKEN_STORE=file\n")
	b.WriteString("unset KVO_SERVER\n")
	return b.String(), nil
}

// PairEnv is the file the two-machine metal tests source. KEVASO_METAL_* is m1 and
// KEVASO_METAL2_* is m2, the same names a metalenv file uses for a real pair. Both external
// addresses are the lab host's public address, where the forwarded ports land. APIPort is
// that address's port for m1's API (the slot port); the tests read it as KEVASO_METAL_API_PORT.
// HostPorts is guest port → the slot port the Mac dials (KEVASO_METAL_PORT_<guest>).
// There is no KVO_CONFIG: Kevaso is not installed, and the tests run kvoadm themselves.
type PairEnv struct {
	Name       string
	Host       string // ubuntu@public-ip, no port
	M1SSH      int
	M2SSH      int
	KeyPath    string
	M1HostKey  string
	M2HostKey  string
	ExternalIP string
	M1Internal string
	M2Internal string
	SpareDisk  string
	APIPort    int         // the lab host port that forwards to m1's 6443 (Ports.API)
	HostPorts  map[int]int // guest port → lab host port, one per PairDials
}

// PairEnvFile renders PairEnv as a shell script.
func PairEnvFile(e PairEnv) (string, error) {
	if err := ValidName(e.Name); err != nil {
		return "", err
	}
	if e.M1SSH < 1 || e.M2SSH < 1 || e.M1SSH == e.M2SSH || e.APIPort < 1 || e.APIPort > 65535 ||
		e.Host == "" || e.KeyPath == "" || e.M1HostKey == "" || e.M2HostKey == "" ||
		e.ExternalIP == "" || e.M1Internal == "" || e.M2Internal == "" || e.SpareDisk == "" {
		return "", fmt.Errorf("pair env for %s: incomplete", e.Name)
	}
	if e.M1Internal == e.M2Internal {
		return "", fmt.Errorf("pair env for %s: m1 and m2 have the same internal address", e.Name)
	}
	taken := map[int]string{e.M1SSH: "m1 ssh", e.M2SSH: "m2 ssh", e.APIPort: "api"}
	for _, d := range PairDials() {
		h, ok := e.HostPorts[d.Port]
		if !ok || h < 1 || h > 65535 {
			return "", fmt.Errorf("pair env for %s: no host port for %d", e.Name, d.Port)
		}
		if prev, dup := taken[h]; dup {
			return "", fmt.Errorf("pair env for %s: port %d and %s share host port %d", e.Name, d.Port, prev, h)
		}
		taken[h] = fmt.Sprintf("%s:%d", d.Role, d.Port)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# pair lab %s. Two machines, m1 and m2. Kevaso is not installed.\n", e.Name)
	b.WriteString("# Each VM's fresh state is in /var/lib/kvt-baseline, the harness baseline.\n")
	b.WriteString("# source this file, then: go test -tags metal -run '^TestMetal2' ./test/e2e/\n")
	fmt.Fprintf(&b, "export LAB_NAME=%s\n", q(e.Name))
	b.WriteString("export LAB_PAIR=1\n")
	fmt.Fprintf(&b, "export KEVASO_METAL_HOST=%s\n", q(e.Host+":"+strconv.Itoa(e.M1SSH)))
	fmt.Fprintf(&b, "export KEVASO_METAL_KEY=%s\n", q(e.KeyPath))
	fmt.Fprintf(&b, "export KEVASO_METAL_HOSTKEY=%s\n", q(e.M1HostKey))
	fmt.Fprintf(&b, "export KEVASO_METAL_EXTERNAL_IP=%s\n", q(e.ExternalIP))
	fmt.Fprintf(&b, "export KEVASO_METAL_INTERNAL_IP=%s\n", q(e.M1Internal))
	fmt.Fprintf(&b, "export KEVASO_METAL_API_PORT=%s\n", q(strconv.Itoa(e.APIPort)))
	for _, d := range PairDials() {
		fmt.Fprintf(&b, "export KEVASO_METAL_PORT_%d=%s\n", d.Port, q(strconv.Itoa(e.HostPorts[d.Port])))
	}
	fmt.Fprintf(&b, "export KEVASO_METAL2_HOST=%s\n", q(e.Host+":"+strconv.Itoa(e.M2SSH)))
	fmt.Fprintf(&b, "export KEVASO_METAL2_KEY=%s\n", q(e.KeyPath))
	fmt.Fprintf(&b, "export KEVASO_METAL2_HOSTKEY=%s\n", q(e.M2HostKey))
	fmt.Fprintf(&b, "export KEVASO_METAL2_EXTERNAL_IP=%s\n", q(e.ExternalIP))
	fmt.Fprintf(&b, "export KEVASO_METAL2_INTERNAL_IP=%s\n", q(e.M2Internal))
	fmt.Fprintf(&b, "export KEVASO_METAL2_SPARE_DISK=%s\n", q(e.SpareDisk))
	b.WriteString("unset KVO_CONFIG\n")
	b.WriteString("unset KVO_SERVER\n")
	return b.String(), nil
}

// q quotes a shell word. Names have already passed ValidName; this still keeps a space or a
// quote in a path from splitting.
func q(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
