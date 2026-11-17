package e2e

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"kevaso.com/core/testbed/lab"
	"kevaso.com/core/testbed/remote"
)

// metalDialPort is the port this Mac dials for a service that listens on real
// on the machine. KEVASO_METAL_PORT_<real> is a pair lab's slot port; unset means
// real, the port a real machine listens on.
func metalDialPort(real int) (int, error) {
	if real < 1 || real > 65535 {
		return 0, fmt.Errorf("port %d: want a TCP port", real)
	}
	key := "KEVASO_METAL_PORT_" + strconv.Itoa(real)
	p := os.Getenv(key)
	if p == "" {
		return real, nil
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%s %q: want a TCP port", key, p)
	}
	return n, nil
}

// metalDialPorts checks every port a pair lab publishes. setUpPair calls it so a
// bad value fails before the suite starts.
func metalDialPorts() error {
	for _, d := range lab.PairDials() {
		if _, err := metalDialPort(d.Port); err != nil {
			return err
		}
	}
	return nil
}

// metalLabHost is the lab host's address from KEVASO_METAL_HOST (user@address:port).
// Empty when that variable is unset, which is how a check that does not need it
// stays quiet.
func metalLabHost() (string, error) {
	host := os.Getenv("KEVASO_METAL_HOST")
	if host == "" {
		return "", nil
	}
	_, addr, _, err := remote.ParseTarget(host)
	if err != nil {
		return "", fmt.Errorf("KEVASO_METAL_HOST: %w", err)
	}
	return addr, nil
}

// labForwardsTo reports whether a pair lab publishes real to this machine.
// The role in PairDials says which env variable holds that machine's external address.
func labForwardsTo(external string, real int) bool {
	for _, d := range lab.PairDials() {
		if d.Port != real {
			continue
		}
		key := "KEVASO_METAL_EXTERNAL_IP"
		if d.Role == "m2" {
			key = "KEVASO_METAL2_EXTERNAL_IP"
		}
		return os.Getenv(key) == external
	}
	return false
}

// metalDialTarget is host:port this Mac dials for a service listening on real
// on the machine whose external address is external. sshAddr is the lab host
// (Config.Address). When KEVASO_METAL_PORT_<real> is unset, the dial is
// external:real, which is what a real machine listens on. When it is set and
// this machine is the one the lab forwards that port to, the dial is
// sshAddr:slotPort: the lab host DNATs that to external:real, so the packet
// arrives on the external NIC with that destination. A check of the other
// machine dials external:real. A pair lab's external address is not routed
// from this Mac, so that dial fails closed. The one-machine suite uses this
// for every dial from this Mac to KEVASO_METAL_EXTERNAL_IP.
func metalDialTarget(external, sshAddr string, real int) (string, error) {
	slot, err := metalDialPort(real)
	if err != nil {
		return "", err
	}
	host, port := external, real
	if slot != real && labForwardsTo(external, real) {
		if sshAddr == "" {
			return "", fmt.Errorf("port %d is published on the lab host, and there is no lab host address", real)
		}
		host, port = sshAddr, slot
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
