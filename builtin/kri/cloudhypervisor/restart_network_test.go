package cloudhypervisor

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// A kevasod restart (or a runtime's Install retried every minute) must not replace the live silo
// firewall, which RunNetwork keeps, with the empty baseline: that drops every silo's host ports,
// allowFrom, NAT and its anti-spoofing rules until the next full apply. After a reboot (no table)
// the baseline is loaded, so silos start default-denied.
func TestSetupNetworkKeepsALiveRulesetAndLoadsTheBaselineAfterAReboot(t *testing.T) {
	loads := func(tableThere bool) bool {
		h := newFakeHost()
		h.answer = func(cmd string) (string, error) {
			if strings.HasPrefix(cmd, "nft list table inet kevaso") && !tableThere {
				return "", errors.New("no such table")
			}
			return "", nil
		}
		if err := SetupNetwork(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		return slices.Contains(h.commands(), "nft -f /etc/kevaso-silos.nft")
	}
	if loads(true) {
		t.Fatal("restart: the live ruleset was replaced by the baseline")
	}
	if !loads(false) {
		t.Fatal("reboot: no baseline loaded before silos start")
	}
}

// After a boot, cloud-hypervisor and the container runtime both set up kvbr0. Each sees no link,
// then both run ip link add: the second answers "RTNETLINK answers: File exists" and that runtime
// was marked Failed until the next minute. The link the loser finds is the bridge, so setup
// finishes (gateway address, up, firewall). A device that already has the name and is not a bridge
// still fails.
func TestSetupNetworkWhenTheBridgeAppearsUnderIt(t *testing.T) {
	const (
		bridgeShown = "2: kvbr0: <BROADCAST,MULTICAST> mtu 1500 qdisc noqueue state DOWN mode DEFAULT\n    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0"
		notABridge  = "2: kvbr0: <BROADCAST,NOARP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT\n    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff\n    dummy addrgenmode eui64 numtxqueues 1 numrxqueues 1"
	)
	script := func(detail string, addrExists bool) *fakeHost {
		h := newFakeHost()
		h.answer = func(cmd string) (string, error) {
			switch cmd {
			case "ip link show " + Bridge:
				return `Device "kvbr0" does not exist.`, errors.New("exit 1")
			case "ip link add " + Bridge + " type bridge":
				return "RTNETLINK answers: File exists", errors.New("exit 2")
			case "ip -d link show " + Bridge:
				return detail, nil
			case "ip addr add " + Gateway.String() + "/24 dev " + Bridge:
				if addrExists {
					return "RTNETLINK answers: File exists", errors.New("exit 2")
				}
			case "nft list table inet kevaso":
				return "", errors.New("no such table")
			}
			return "", nil
		}
		return h
	}

	h := script(bridgeShown, true)
	if err := SetupNetwork(context.Background(), h); err != nil {
		t.Fatalf("bridge already there: %v", err)
	}
	for _, want := range []string{
		"ip -d link show " + Bridge,
		"ip addr add " + Gateway.String() + "/24 dev " + Bridge,
		"ip link set " + Bridge + " up",
		"sysctl -qw net.ipv4.ip_forward=1",
		"nft -f /etc/kevaso-silos.nft",
	} {
		if !slices.Contains(h.commands(), want) {
			t.Fatalf("setup stopped once the bridge existed: missing %q in\n%s", want, strings.Join(h.commands(), "\n"))
		}
	}

	h = script(notABridge, false)
	err := SetupNetwork(context.Background(), h)
	if err == nil || !strings.Contains(err.Error(), "not a bridge") {
		t.Fatalf("existing non-bridge: got %v", err)
	}
	if !slices.Contains(h.commands(), "ip -d link show "+Bridge) {
		t.Fatalf("non-bridge: the link was not inspected: %v", h.commands())
	}
	if slices.Contains(h.commands(), "nft -f /etc/kevaso-silos.nft") {
		t.Fatal("non-bridge: the silo firewall was loaded on it")
	}
}
