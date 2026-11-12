package apiserver

import (
	"fmt"
	"net"
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
	case *v1.Grant:
		for _, r := range o.Spec.Egress {
			if _, err := r.Parse(); err != nil {
				errs = append(errs, err.Error())
			}
		}
		for _, sec := range o.Spec.Secrets {
			if sec.To != nil {
				if _, err := (v1.EgressRule{To: sec.To.Host}).Parse(); err != nil || strings.Contains(sec.To.Host, "*") || strings.Contains(sec.To.Host, "/") {
					errs = append(errs, fmt.Sprintf("secret %s: to.host %q must be one host name", sec.Name, sec.To.Host))
				}
				if f := sec.To.Format; f != "" && strings.Count(f, "{{value}}") != 1 {
					errs = append(errs, fmt.Sprintf("secret %s: to.format must contain {{value}} once", sec.Name))
				}
				if h := sec.To.Header; h != "" && strings.ContainsAny(h, " :\r\n") {
					errs = append(errs, fmt.Sprintf("secret %s: to.header %q isn't a header name", sec.Name, h))
				}
			}
			if sec.Path != "" && (!strings.HasPrefix(sec.Path, "/run/") || strings.Contains(sec.Path, "..")) {
				errs = append(errs, fmt.Sprintf("secret %s: path %q must be under /run/ (tmpfs: a secret file never reaches the silo's disk), without ..", sec.Name, sec.Path))
			}
		}
	case *v1.Ingress:
		for _, h := range o.Spec.Hosts {
			if _, err := (v1.EgressRule{To: h}).Parse(); err != nil || strings.Contains(h, "/") || net.ParseIP(h) != nil {
				errs = append(errs, fmt.Sprintf("spec.hosts: %q isn't a host name", h))
			}
		}
	case *v1.Certificate:
		for _, h := range o.Spec.Hosts {
			if _, err := (v1.EgressRule{To: h}).Parse(); err != nil || strings.Contains(h, "/") || net.ParseIP(h) != nil {
				errs = append(errs, fmt.Sprintf("spec.hosts: %q isn't a host name", h))
			}
		}
	case *v1.Secret:
		if len(o.Spec.Value) > 64<<10 {
			errs = append(errs, "spec.value: at most 64 KiB")
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
