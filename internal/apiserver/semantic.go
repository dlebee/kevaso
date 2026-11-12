package apiserver

import (
	"fmt"
	"net/netip"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// semantic checks what CEL can't say well: addresses and ranges.
func semantic(obj meta.Object) []string {
	var errs []string
	cidrs := func(field string, list []string) {
		for _, c := range list {
			if _, err := netip.ParsePrefix(c); err != nil {
				if _, err := netip.ParseAddr(c); err != nil {
					errs = append(errs, fmt.Sprintf("%s: %q isn't an address or CIDR", field, c))
				}
			}
		}
	}
	switch o := obj.(type) {
	case *v1.Silo:
		if sv := o.Spec.Service; sv != nil {
			if sv.HostPort != nil {
				cidrs("service.hostPort.allowFrom", sv.HostPort.AllowFrom)
			}
			if sv.LoadBalancer != nil {
				cidrs("service.loadBalancer.allowFrom", sv.LoadBalancer.AllowFrom)
			}
		}
		for _, a := range o.Spec.AllowFrom {
			if strings.Count(a.Silo, "/") > 1 {
				errs = append(errs, fmt.Sprintf("allowFrom: %q: want NAME or NAMESPACE/NAME", a.Silo))
			}
		}
	case *v1.IPPool:
		for _, a := range o.Spec.Addresses {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				addr, aerr := netip.ParseAddr(a)
				if aerr != nil {
					errs = append(errs, fmt.Sprintf("spec.addresses: %q isn't an address or CIDR", a))
					continue
				}
				p = netip.PrefixFrom(addr, addr.BitLen())
			}
			if !p.Addr().Is4() {
				errs = append(errs, fmt.Sprintf("spec.addresses: %q: IPv6 pools come later; IPv4 for now", a))
			}
		}
	}
	return errs
}
