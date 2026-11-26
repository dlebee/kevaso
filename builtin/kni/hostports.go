package kni

import (
	"fmt"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

// hpKey is one host address, protocol and number.
type hpKey struct {
	addr, proto string
	port        int
}

// reservedWhy says why n may not be a host port: the platform's fixed listeners, then this
// host's own. Empty: it may.
func reservedWhy(h Host, n int) string {
	if why := v1.ReservedHostPort(n); why != "" {
		return why
	}
	return h.Reserved[n]
}

// hostPortOwners is the one non-refused silo that asks for each host address, protocol and
// number. Two askers, or none: the key is absent, and the address is opened for nobody. A silo
// whose HostPorts condition is false does not ask. A number the platform listens on is not
// opened for anyone, so it is not claimed here either.
func hostPortOwners(local []Silo, h Host) map[hpKey]string {
	want := map[hpKey]map[string]bool{}
	for _, s := range local {
		if !s.IP.IsValid() || s.HostPortsRefused {
			continue
		}
		for _, p := range s.open() {
			if !okPort(p.Number) || !okPort(p.HostNumber()) || !okProto(lower(p.Protocol)) {
				continue
			}
			if reservedWhy(h, p.HostNumber()) != "" {
				continue
			}
			proto, at := lower(p.Protocol), p.HostNumber()
			for _, a := range hostAddrs(h, s, p) {
				k := hpKey{a.String(), proto, at}
				if want[k] == nil {
					want[k] = map[string]bool{}
				}
				want[k][s.Key] = true
			}
		}
	}
	out := map[hpKey]string{}
	for k, keys := range want {
		if len(keys) == 1 {
			for key := range keys {
				out[k] = key
			}
		}
	}
	return out
}

// siloGatewaySet is every host's own address on the silo network: 10.64.N.1 for each N. A silo
// reaches none of them. Known silos are not enough: a host with no silo still has .1, and this
// host does not list every other host's index.
func siloGatewaySet() string {
	p := make([]string, 256)
	for i := range p {
		p[i] = fmt.Sprintf("10.64.%d.1", i)
	}
	return "{ " + strings.Join(p, ", ") + " }"
}
