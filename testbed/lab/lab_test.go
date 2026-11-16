package lab

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"kevaso.com/core/testbed/remote"
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
	if p.SSH("m1") != p.SysSSH || p.SSH("m2") != p.W1SSH {
		t.Fatal("pair ssh ports")
	}
	if err := checkPairDials(); err != nil {
		t.Fatal(err)
	}
	for slot := 1; slot <= MaxLabs; slot++ {
		ps := PortsForMust(t, slot)
		base := PortBase + slot*100
		seen := map[int]string{ps.SysSSH: "sys", ps.W1SSH: "w1", ps.W2SSH: "w2", ps.API: "api"}
		for _, d := range PairDials() {
			h, err := ps.Dial(d.Port)
			if err != nil {
				t.Fatalf("slot %d port %d: %v", slot, d.Port, err)
			}
			if h != base+d.Off || h < base || h >= base+100 {
				t.Fatalf("slot %d port %d: host port %d, want %d", slot, d.Port, h, base+d.Off)
			}
			if prev, ok := seen[h]; ok {
				t.Fatalf("slot %d: host port %d is %s and %s:%d", slot, h, prev, d.Role, d.Port)
			}
			if h == d.Port {
				t.Fatalf("slot %d publishes guest port %d on itself", slot, d.Port)
			}
			seen[h] = d.Role
		}
	}
	if _, err := (Ports{}).Dial(80); !errors.Is(err, ErrBadSlot) {
		t.Fatalf("empty ports: %v", err)
	}
	if _, err := PortsForMust(t, 1).Dial(9); err == nil {
		t.Fatal("an unpublished port was accepted")
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
	if strings.Contains(fw, "dport 6443 ") || strings.Contains(fw, "dport 80 ") {
		t.Errorf("a node lab forwards a well-known host port:\n%s", fw)
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
		"virsh destroy 'kvl-smoke-m1'",
		"virsh destroy 'kvl-smoke-m2'",
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
	if strings.Contains(text, "KEVASO_METAL2_") || strings.Contains(text, "LAB_PAIR") {
		t.Fatalf("a node lab's env names the pair:\n%s", text)
	}
}

func TestPair(t *testing.T) {
	m1, m2 := PairNodes()[0], PairNodes()[1]
	if m1.Role != "m1" || m2.Role != "m2" || m1.VCPU != 4 || m2.VCPU != 4 || m1.MemoryMiB != 8192 || m2.MemoryMiB != 8192 || m1.DiskGiB != 40 || m2.DiskGiB != 40 {
		t.Fatalf("sizes: %+v %+v", m1, m2)
	}
	if m1.SpareSerial != "" || m2.SpareSerial != SpareSerial || SpareDiskGiB != 20 {
		t.Fatalf("spare: %+v %+v %d", m1, m2, SpareDiskGiB)
	}
	if SpareByID != "/dev/disk/by-id/virtio-"+SpareSerial {
		t.Fatal(SpareByID)
	}

	xml, err := PairNetworkXML("pr", 3, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<name>kvl-pr</name>",
		"<forward mode='open'/>",
		"<bridge name='kvlbr3'",
		"<hostname>m1.pr.lab.test</hostname>",
		"<hostname>m2.pr.lab.test</hostname>",
		"mac='52:54:00:77:03:0a' name='m1' ip='10.77.3.10'",
		"mac='52:54:00:77:03:0b' name='m2' ip='10.77.3.11'",
		"start='10.77.3.10' end='10.77.3.11'",
		"address=/.pr.lab.test/10.77.3.10",
	} {
		if !strings.Contains(xml, want) {
			t.Errorf("pair network lacks %q\n%s", want, xml)
		}
	}
	for _, absent := range []string{"sys.pr", "w1.pr", "w2.pr", "10.77.3.12", "e046", "default"} {
		if strings.Contains(xml, absent) {
			t.Errorf("pair network contains %q\n%s", absent, xml)
		}
	}

	d1, err := DomainXML("pr", 3, m1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := DomainXML("pr", 3, m2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d1, "<name>kvl-pr-m1</name>") || !strings.Contains(d1, "<vcpu placement='static'>4</vcpu>") || !strings.Contains(d1, "<memory unit='MiB'>8192</memory>") {
		t.Fatalf("m1 domain:\n%s", d1)
	}
	if strings.Contains(d1, "vdb") || strings.Contains(d1, SpareSerial) || strings.Contains(d1, "spare") {
		t.Fatalf("m1 has the spare disk:\n%s", d1)
	}
	for _, want := range []string{
		"<name>kvl-pr-m2</name>",
		"<target dev='vdb' bus='virtio'/>",
		"<serial>" + SpareSerial + "</serial>",
		SpareDisk("pr"),
		"mode='host-passthrough' check='none' migratable='off'",
	} {
		if !strings.Contains(d2, want) {
			t.Errorf("m2 domain lacks %q\n%s", want, d2)
		}
	}
	if strings.Contains(d2, BaseImage) || strings.Contains(d2, "e046") {
		t.Fatalf("m2 domain names the base image:\n%s", d2)
	}
	sys, err := DomainXML("pr", 3, Nodes()[0])
	if err != nil || strings.Contains(sys, "vdb") || strings.Contains(sys, SpareSerial) {
		t.Fatalf("a system node gained the spare disk: %v\n%s", err, sys)
	}
	bad := m2
	bad.SpareSerial = "kvl spare"
	if _, err := DomainXML("pr", 3, bad); err == nil {
		t.Fatal("a serial with a space was accepted")
	}

	fw, err := PairForwardScript("pr", 3, "enp5s0f0", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"iifname 'enp5s0f0' tcp dport 21322 dnat ip to 10.77.3.10:22",
		"tcp dport 21323 dnat ip to 10.77.3.11:22",
		"iifname 'enp5s0f0' tcp dport 21343 dnat ip to 10.77.3.10:6443",
		"iifname 'kvlbr3' ip daddr 203.0.113.10 tcp dport 21343 dnat ip to 10.77.3.10:6443",
		"iifname 'kvlbr3' ip daddr 203.0.113.10 tcp dport 6443 dnat ip to 10.77.3.10:6443",
		"iifname 'enp5s0f0' tcp dport 21380 dnat ip to 10.77.3.10:80",
		"iifname 'kvlbr3' ip daddr 203.0.113.10 tcp dport 21380 dnat ip to 10.77.3.10:80",
		"tcp dport 21344 dnat ip to 10.77.3.10:443",
		"tcp dport 21360 dnat ip to 10.77.3.10:18160",
		"tcp dport 21325 dnat ip to 10.77.3.11:18200",
		"tcp dport 21326 dnat ip to 10.77.3.11:18201",
		"tcp dport 21327 dnat ip to 10.77.3.11:18210",
		"iifname 'kvlbr3' ip daddr 203.0.113.10 tcp dport 21327 dnat ip to 10.77.3.11:18210",
		"public port 80 is already forwarded; this lab will not publish it, so TestMetal2LongSoakSetup runs one pair lab at a time",
		"iifname 'enp5s0f0' tcp dport 80 dnat ip to 10.77.3.10:80",
		"iifname 'kvlbr3' ip daddr 203.0.113.10 tcp dport 80 dnat ip to 10.77.3.10:80",
		"oifname 'kvlbr3' ct status dnat masquerade",
		"ip saddr 10.77.3.0/24 oifname 'enp5s0f0' masquerade",
		"port 21380 is already forwarded on the lab host",
		"port 21380 is in use on the lab host",
	} {
		if !strings.Contains(fw, want) {
			t.Errorf("pair nft lacks %q\n%s", want, fw)
		}
	}
	note := strings.Index(fw, "public port 80 is already forwarded")
	open80 := strings.Index(fw, "tcp dport 80 dnat ip to 10.77.3.10:80")
	if note < 0 || open80 < note || strings.Index(fw, "\nelse\n") < note {
		t.Fatalf("public port 80 is not behind the already-forwarded check\n%s", fw)
	}
	for _, line := range strings.Split(fw, "\n") {
		if strings.Contains(line, "public port 80") && strings.Contains(line, "exit 1") {
			t.Errorf("public port 80 still fails the lab: %s", line)
		}
	}
	for _, shared := range []string{"tcp dport 443 ", "tcp dport 18160 ", "tcp dport 18200 ", "tcp dport 18201 ", "tcp dport 18210 "} {
		if strings.Contains(fw, shared) {
			t.Errorf("a pair lab publishes %q on the lab host\n%s", shared, fw)
		}
	}
	if strings.Contains(fw, "iifname 'enp5s0f0' tcp dport 6443 ") || strings.Contains(fw, "port 6443 is already forwarded") {
		t.Errorf("a pair lab publishes public port 6443:\n%s", fw)
	}
	other, err := PairForwardScript("pr", 1, "enp5s0f0", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(other, "tcp dport 21143 dnat ip to 10.77.1.10:6443") || strings.Contains(other, "dport 21343 ") {
		t.Errorf("slot 1 does not use its own API port:\n%s", other)
	}
	for _, slot1 := range []string{
		"tcp dport 21180 dnat ip to 10.77.1.10:80",
		"tcp dport 21144 dnat ip to 10.77.1.10:443",
		"tcp dport 21160 dnat ip to 10.77.1.10:18160",
		"tcp dport 21125 dnat ip to 10.77.1.11:18200",
		"tcp dport 21126 dnat ip to 10.77.1.11:18201",
		"tcp dport 21127 dnat ip to 10.77.1.11:18210",
	} {
		if !strings.Contains(other, slot1) {
			t.Errorf("slot 1 lacks %q\n%s", slot1, other)
		}
		port := strings.Fields(slot1)[2]
		if strings.Contains(fw, "dport "+port+" ") {
			t.Errorf("slot 3 also publishes host port %s", port)
		}
	}
	for _, absent := range []string{"10.77.3.12", "dport 21324", "iptables", "e046", "default"} {
		if strings.Contains(fw, absent) {
			t.Errorf("pair nft contains %q\n%s", absent, fw)
		}
	}
	if _, err := PairForwardScript("pr", 3, "enp0; rm", "203.0.113.10"); err == nil {
		t.Fatal("an unsafe interface was accepted")
	}
	if _, err := PairForwardScript("pr", 3, "enp5s0f0", "10.77.3.1"); err == nil {
		t.Fatal("a private address was accepted as the public address")
	}
	if _, err := PairForwardScript("pr", 3, "enp5s0f0", "203.0.113.10;id"); err == nil {
		t.Fatal("a public address with a command was accepted")
	}

	m1pin := "SHA256:" + strings.Repeat("A", 43)
	m2pin := "SHA256:" + strings.Repeat("B", 43)
	key := "/work/testbed/lab/.labs/pr/id_ed25519"
	hostPorts, err := PortsForMust(t, 3).HostPorts()
	if err != nil {
		t.Fatal(err)
	}
	env, err := PairEnvFile(PairEnv{
		Name: "pr", Host: "ubuntu@203.0.113.10", M1SSH: 21322, M2SSH: 21323,
		KeyPath: key, M1HostKey: m1pin, M2HostKey: m2pin, ExternalIP: "203.0.113.10",
		M1Internal: "10.77.3.10", M2Internal: "10.77.3.11", SpareDisk: SpareByID, APIPort: 21343,
		HostPorts: hostPorts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(env, "PRIVATE KEY") || strings.Contains(env, "KVO_CONFIG=") {
		t.Fatalf("pair env has a key or a kvo config:\n%s", env)
	}
	got := exports(env)
	getenv := func(k string) string { return got[k] }
	c1, err := remote.FromEnv(getenv)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := remote.FromEnvPrefix(getenv, remote.SecondPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if c1.User != "ubuntu" || c1.Address != "203.0.113.10" || c1.Port != 21322 || c1.KeyFile != key || c1.HostKey != m1pin ||
		c1.ExternalIP != "203.0.113.10" || c1.InternalIP != "10.77.3.10" || c1.SpareDisk != "" {
		t.Fatalf("m1 from the env file: %+v", c1)
	}
	if c2.User != "ubuntu" || c2.Address != "203.0.113.10" || c2.Port != 21323 || c2.KeyFile != key || c2.HostKey != m2pin ||
		c2.ExternalIP != "203.0.113.10" || c2.InternalIP != "10.77.3.11" || c2.SpareDisk != SpareByID {
		t.Fatalf("m2 from the env file: %+v", c2)
	}
	if got["LAB_NAME"] != "pr" || got["LAB_PAIR"] != "1" || got["KEVASO_METAL_API_PORT"] != "21343" ||
		got["KEVASO_METAL_PORT_80"] != "21380" || got["KEVASO_METAL_PORT_443"] != "21344" ||
		got["KEVASO_METAL_PORT_18160"] != "21360" || got["KEVASO_METAL_PORT_18200"] != "21325" ||
		got["KEVASO_METAL_PORT_18201"] != "21326" || got["KEVASO_METAL_PORT_18210"] != "21327" {
		t.Fatalf("lab vars: %v", got)
	}
	if _, err := PairEnvFile(PairEnv{Name: "pr"}); err == nil {
		t.Fatal("an incomplete pair env was accepted")
	}
	same := PairEnv{
		Name: "pr", Host: "ubuntu@203.0.113.10", M1SSH: 21322, M2SSH: 21323,
		KeyPath: key, M1HostKey: m1pin, M2HostKey: m2pin, ExternalIP: "203.0.113.10",
		M1Internal: "10.77.3.10", M2Internal: "10.77.3.10", SpareDisk: SpareByID, APIPort: 21343,
		HostPorts: hostPorts,
	}
	clash := PairEnv{
		Name: "pr", Host: "ubuntu@203.0.113.10", M1SSH: 21322, M2SSH: 21323,
		KeyPath: key, M1HostKey: m1pin, M2HostKey: m2pin, ExternalIP: "203.0.113.10",
		M1Internal: "10.77.3.10", M2Internal: "10.77.3.11", SpareDisk: SpareByID, APIPort: 21343,
		HostPorts: map[int]int{80: 21380, 443: 21380, 18160: 21360, 18200: 21325, 18201: 21326, 18210: 21327},
	}
	if _, err := PairEnvFile(clash); err == nil {
		t.Fatal("two guest ports sharing a host port was accepted")
	}
	if _, err := PairEnvFile(same); err == nil {
		t.Fatal("m1 and m2 sharing an internal address was accepted")
	}
}

// exports reads the export lines of an env file. Values are single-quoted.
func exports(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "export ")
		if !ok {
			continue
		}
		k, v, ok := strings.Cut(rest, "=")
		if !ok {
			continue
		}
		if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
			v = strings.ReplaceAll(v[1:len(v)-1], `'\''`, "'")
		}
		out[k] = v
	}
	return out
}
