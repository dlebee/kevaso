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
