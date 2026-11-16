package e2e

import (
	"fmt"
	"os"
	"strconv"

	"kevaso.com/core/testbed/lab"
)

// metalDialPort is the port this Mac dials for a service that listens on real
// on the machine. KEVASO_METAL_PORT_<real> is a pair lab's slot port; unset means
// real, the port a real pair listens on.
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
