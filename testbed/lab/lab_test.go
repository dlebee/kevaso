package lab

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestValidName(t *testing.T) {
	for _, ok := range []string{"a", "smoke", "a1", "a-b", "abcdefghijkl"} {
		if err := ValidName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	if len("abcdefghijkl") != MaxName {
		t.Fatal("the 12-character example isn't MaxName")
	}
	for _, bad := range []string{"", "A", "Smoke", "abcdefghijklm", "-a", "a-", "a.b", "ab c", "a/b", "..", "smoke;rm", "e046", "default"} {
		err := ValidName(bad)
		// e046 and default are fine labels. They must still not be used as a prefix that
		// reaches the base image: that is the render tests. Only the malformed ones fail here.
		if bad == "e046" || bad == "default" {
			if err != nil {
				t.Errorf("%q: %v", bad, err)
			}
			continue
		}
		if !errors.Is(err, ErrBadName) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestAllocateSlot(t *testing.T) {
	s, err := AllocateSlot(nil)
	if err != nil || s != 1 {
		t.Fatalf("empty: %d %v", s, err)
	}
	s, err = AllocateSlot([]int{1, 2, 4})
	if err != nil || s != 3 {
		t.Fatalf("hole: %d %v", s, err)
	}
	s, err = AllocateSlot([]int{1, 2, 3, 4, 5})
	if err != nil || s != 6 {
		t.Fatalf("last: %d %v", s, err)
	}
	if _, err := AllocateSlot([]int{1, 2, 3, 4, 5, 6}); !errors.Is(err, ErrCap) {
		t.Fatalf("full: %v", err)
	}
	// Six labs, even with a duplicated slot and a free number, are still six.
	if _, err := AllocateSlot([]int{1, 1, 1, 1, 1, 1}); !errors.Is(err, ErrCap) {
		t.Fatalf("six duplicates: %v", err)
	}
}

func TestPorts(t *testing.T) {
	p, err := PortsFor(1)
	if err != nil || p != (Ports{SysSSH: 21122, W1SSH: 21123, W2SSH: 21124, API: 21143}) {
		t.Fatalf("slot 1: %+v %v", p, err)
	}
	p, err = PortsFor(6)
	if err != nil || p.SysSSH != 21622 || p.API != 21643 {
		t.Fatalf("slot 6: %+v %v", p, err)
	}
	if _, err := PortsFor(0); !errors.Is(err, ErrBadSlot) {
		t.Fatalf("slot 0: %v", err)
	}
	if _, err := PortsFor(7); !errors.Is(err, ErrBadSlot) {
		t.Fatalf("slot 7: %v", err)
	}
	if p.SSH("sys") != p.SysSSH || PortsForMust(t, 2).SSH("w2") != 21224 {
		t.Fatal("role ports")
	}
}

func PortsForMust(t *testing.T, slot int) Ports {
	t.Helper()
	p, err := PortsFor(slot)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRefusals(t *testing.T) {
	if err := RefuseUp("Bad", false, false, false, 0); !errors.Is(err, ErrBadName) {
		t.Fatalf("bad name: %v", err)
	}
	if err := RefuseUp("smoke", false, false, true, 0); !errors.Is(err, ErrKevasod) || !strings.Contains(err.Error(), "firewall") {
		t.Fatalf("kevasod: %v", err)
	}
	if err := RefuseUp("smoke", true, false, false, 1); !errors.Is(err, ErrExists) {
		t.Fatalf("exists: %v", err)
	}
	if err := RefuseUp("smoke", true, true, false, MaxLabs); err != nil {
		t.Fatalf("recreate at the cap: %v", err)
	}
	if err := RefuseUp("seventh", false, false, false, MaxLabs); !errors.Is(err, ErrCap) || !strings.Contains(err.Error(), "7th") {
		t.Fatalf("seventh: %v", err)
	}
	if err := RefuseUp("smoke", false, false, false, MaxLabs-1); err != nil {
		t.Fatalf("sixth: %v", err)
	}
	if !KevasodActive("active") || !KevasodActive("activating") || KevasodActive("inactive") || KevasodActive("failed") {
		t.Fatal("kevasod state")
	}
}

func TestNetworkAndDomain(t *testing.T) {
	xml, err := NetworkXML("smoke", 1, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<name>kvl-smoke</name>",
		"<forward mode='open'/>",
		"<bridge name='kvlbr1'",
		"<domain name='lab.test'",
		"<hostname>sys.smoke.lab.test</hostname>",
		"<hostname>w1.smoke.lab.test</hostname>",
		"<hostname>w2.smoke.lab.test</hostname>",
		"address='10.77.1.1'",
		"mac='52:54:00:77:01:0a' name='sys' ip='10.77.1.10'",
		"mac='52:54:00:77:01:0b' name='w1' ip='10.77.1.11'",
		"mac='52:54:00:77:01:0c' name='w2' ip='10.77.1.12'",
		"address=/.smoke.lab.test/10.77.1.10",
	} {
		if !strings.Contains(xml, want) {
			t.Errorf("network XML lacks %q\n%s", want, xml)
		}
	}
	if strings.Contains(xml, "e046") || strings.Contains(xml, "default") || strings.Contains(xml, "192.168.122") {
		t.Errorf("network XML names something that isn't this lab:\n%s", xml)
	}
	plain, err := NetworkXML("smoke", 1, false)
	if err != nil || strings.Contains(plain, "dnsmasq:option") {
		t.Fatalf("without the wildcard: %v\n%s", err, plain)
	}
	if !strings.Contains(plain, "sys.smoke.lab.test") {
		t.Fatal("the three names were dropped with the wildcard")
	}

	for _, n := range Nodes() {
		dom, err := DomainXML("smoke", 1, n)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(dom, "<name>"+VMName("smoke", n.Role)+"</name>") ||
			!strings.Contains(dom, "<memory unit='MiB'>"+strconv.Itoa(n.MemoryMiB)+"</memory>") ||
			!strings.Contains(dom, "<vcpu placement='static'>"+strconv.Itoa(n.VCPU)+"</vcpu>") ||
			!strings.Contains(dom, "mode='host-passthrough' check='none' migratable='off'") ||
			!strings.Contains(dom, "cache='none' io='native'") ||
			!strings.Contains(dom, Disk("smoke", n.Role)) ||
			!strings.Contains(dom, Seed("smoke", n.Role)) ||
			!strings.Contains(dom, MAC(1, n.Octet)) ||
			!strings.Contains(dom, "<source network='kvl-smoke'/>") {
			t.Errorf("%s domain:\n%s", n.Role, dom)
		}
		if strings.Contains(dom, "e046-node") || strings.Contains(dom, "network='default'") {
			t.Errorf("%s domain names something else:\n%s", n.Role, dom)
		}
	}
	sys := Nodes()[0]
	w := Nodes()[1]
	if sys.VCPU != 2 || sys.MemoryMiB != 4096 || sys.DiskGiB != 20 || w.VCPU != 4 || w.MemoryMiB != 8192 || w.DiskGiB != 40 {
		t.Fatalf("sizes: %+v %+v", sys, w)
	}
}

func TestCloudInitAndForwardAndDestroy(t *testing.T) {
	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTests kvl-smoke"
	ud := UserData(pub)
	if !strings.Contains(ud, "name: ubuntu") || !strings.Contains(ud, "NOPASSWD:ALL") || !strings.Contains(ud, strconv.Quote(pub)) {
		t.Fatalf("user-data:\n%s", ud)
	}
	if strings.Contains(ud, "PRIVATE KEY") || strings.Contains(ud, "BEGIN OPENSSH") {
		t.Fatal("user-data contains a private key")
	}
	md := MetaData("smoke", "sys")
	if !strings.Contains(md, "instance-id: kvl-smoke-sys") || !strings.Contains(md, "local-hostname: kvl-smoke-sys") {
		t.Fatalf("meta-data:\n%s", md)
	}

	fw, err := ForwardScript("smoke", 1, "enp5s0f0")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"nft add table inet kvl",
		"kvl-smoke-pre",
		"kvl-smoke-post",
		"iifname 'enp5s0f0' tcp dport 21122 dnat ip to 10.77.1.10:22",
		"tcp dport 21123 dnat ip to 10.77.1.11:22",
		"tcp dport 21124 dnat ip to 10.77.1.12:22",
		"tcp dport 21143 dnat ip to 10.77.1.10:6443",
		"oifname 'kvlbr1' ct status dnat masquerade",
		"ip saddr 10.77.1.0/24 oifname 'enp5s0f0' masquerade",
	} {
		if !strings.Contains(fw, want) {
			t.Errorf("nft rules lack %q\n%s", want, fw)
		}
	}
	if strings.Contains(fw, "iptables") || strings.Contains(fw, "libvirt") || strings.Contains(fw, "delete table ip") {
		t.Errorf("nft rules touch another table:\n%s", fw)
	}
	if _, err := ForwardScript("smoke", 1, "enp0; rm"); err == nil {
		t.Fatal("an unsafe interface was accepted")
	}

	del, err := DestroyScript("smoke")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"virsh destroy 'kvl-smoke-sys'",
		"virsh destroy 'kvl-smoke-w1'",
		"virsh destroy 'kvl-smoke-w2'",
		"virsh net-destroy 'kvl-smoke'",
		"virsh net-undefine 'kvl-smoke'",
		"rm -f /var/lib/libvirt/images/kvl-smoke-*",
		"rm -rf '/root/kvl/smoke'",
		"nft delete chain inet kvl 'kvl-smoke-pre'",
		"nft delete chain inet kvl 'kvl-smoke-post'",
		"nft delete table inet kvl",
	} {
		if !strings.Contains(del, want) {
			t.Errorf("destroy script lacks %q\n%s", want, del)
		}
	}
	for _, bad := range []string{"e046", "virbr0", "net-destroy 'default'", "net-undefine 'default'", "kvl-smoke2", "/root/kvl/smoke2"} {
		if strings.Contains(del, bad) {
			t.Errorf("destroy script mentions %q\n%s", bad, del)
		}
	}
	// The table is removed only after the chain list is empty.
	if strings.Index(del, "grep -q") > strings.Index(del, "nft delete table inet kvl") || !strings.Contains(del, "grep -q '^[[:space:]]*chain '") {
		t.Errorf("the table is deleted without checking it is empty:\n%s", del)
	}
	if _, err := DestroyScript("Bad Name"); err == nil {
		t.Fatal("destroy accepted a bad name")
	}
}

func TestEnvFile(t *testing.T) {
	text, err := EnvFile(Env{
		Name: "smoke", Host: "ubuntu@54.39.243.98", SSHPort: 21122,
		KeyPath: "/work/testbed/lab/.labs/smoke/id_ed25519", HostKey: "SHA256:abc",
		ExternalIP: "54.39.243.98", InternalIP: "10.77.1.10",
		ConfigPath: "/work/testbed/lab/.labs/smoke/config.yaml",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"export LAB_NAME='smoke'",
		"export KEVASO_METAL_HOST='ubuntu@54.39.243.98:21122'",
		"export KEVASO_METAL_KEY='/work/testbed/lab/.labs/smoke/id_ed25519'",
		"export KEVASO_METAL_HOSTKEY='SHA256:abc'",
		"export KEVASO_METAL_EXTERNAL_IP='54.39.243.98'",
		"export KEVASO_METAL_INTERNAL_IP='10.77.1.10'",
		"export KVO_CONFIG='/work/testbed/lab/.labs/smoke/config.yaml'",
		"unset KVO_SERVER",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("env lacks %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "PRIVATE KEY") {
		t.Fatal("env file contains a private key")
	}
}
