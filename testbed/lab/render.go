package lab

import (
	"fmt"
	"strconv"
	"strings"
)

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

// NetworkXML is the libvirt NAT network for one lab. wildcard adds a dnsmasq address rule so
// any name under NAME.lab.test answers with the system node (ingress). The three node names are
// always there; the caller drops the wildcard and defines again when this libvirt rejects it.
func NetworkXML(name string, slot int, wildcard bool) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	if _, err := PortsFor(slot); err != nil {
		return "", err
	}
	var hosts, dhcp strings.Builder
	for _, n := range Nodes() {
		ip := IP(slot, n.Octet)
		fmt.Fprintf(&hosts, "    <host ip='%s'>\n      <hostname>%s</hostname>\n    </host>\n", ip, Hostname(name, n.Role))
		fmt.Fprintf(&dhcp, "        <host mac='%s' name='%s' ip='%s'/>\n", MAC(slot, n.Octet), n.Role, ip)
	}
	var extra string
	if wildcard {
		extra = "  <dnsmasq:options>\n    <dnsmasq:option value='address=/." + name + "." + DNSDomain + "/" + IP(slot, 10) + "'/>\n  </dnsmasq:options>\n"
	}
	return `<network xmlns:dnsmasq='http://libvirt.org/schemas/network/dnsmasq/1.0'>
  <name>` + NetworkName(name) + `</name>
  <forward mode='nat'/>
  <bridge name='` + Bridge(slot) + `' stp='on' delay='0'/>
  <domain name='` + DNSDomain + `' localOnly='yes'/>
  <dns enable='yes'>
` + hosts.String() + `  </dns>
` + extra + `  <ip address='` + IP(slot, 1) + `' netmask='255.255.255.0'>
    <dhcp>
      <range start='` + IP(slot, 10) + `' end='` + IP(slot, 12) + `'/>
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
	serial := "/var/log/libvirt/qemu/" + vm + "-serial.log"
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
    <disk type='file' device='cdrom'>
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
      <source path='` + serial + `'/>
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
// that holds the public address, at a priority just before the iptables dstnat hook, and
// masquerade applies only to connections that rule already rewrote, as they leave the lab bridge.
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
	return b.String(), nil
}

// DestroyScript removes one lab and nothing else: the three domains, the one network, disks and
// logs prefixed kvl-NAME-, /root/kvl/NAME, and that lab's nftables chains. The table goes only
// when no chain is left. A lab that is already gone makes every step a no-op.
func DestroyScript(name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	net := NetworkName(name)
	pre, post := PreChain(name), PostChain(name)
	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("need=0\n")
	for _, n := range Nodes() {
		fmt.Fprintf(&b, "virsh dominfo %s >/dev/null 2>&1 && need=1 || true\n", q(VMName(name, n.Role)))
	}
	fmt.Fprintf(&b, "virsh net-info %s >/dev/null 2>&1 && need=1 || true\n", q(net))
	fmt.Fprintf(&b, "[ -d %s ] && need=1 || true\n", q(StateDir(name)))
	fmt.Fprintf(&b, "ls %s/%s-* >/dev/null 2>&1 && need=1 || true\n", ImageDir, "kvl-"+name)
	fmt.Fprintf(&b, "nft list chain %s %s >/dev/null 2>&1 && need=1 || true\n", Table, q(pre))
	b.WriteString("[ \"$need\" = 1 ] || exit 0\n")
	b.WriteString("mkdir -p " + StateRoot + "\n")
	b.WriteString("exec 9>" + StateRoot + "/.lock\nflock 9\n")
	for _, n := range Nodes() {
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

// q quotes a shell word. Names have already passed ValidName; this still keeps a space or a
// quote in a path from splitting.
func q(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
