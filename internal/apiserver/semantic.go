package apiserver

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

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
		if r := o.Spec.Readiness; r != nil {
			for field, d := range map[string]string{"readiness.period": r.Period, "readiness.timeout": r.Timeout} {
				if d == "" {
					continue
				}
				if v, err := time.ParseDuration(d); err != nil || v <= 0 {
					errs = append(errs, fmt.Sprintf("%s: %q isn't a duration (e.g. 10s)", field, d))
				}
			}
		}
	case *v1.Service:
		for _, p := range o.Spec.Ports {
			if t := p.TargetPort; t != "" {
				if n, err := strconv.Atoi(t); err == nil && (n < 1 || n > 65535) {
					errs = append(errs, fmt.Sprintf("port %s: targetPort %d isn't from 1 to 65535", p.Name, n))
				}
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

// transition checks what may change on an update: an Image's versions are immutable once added
// (an instance on v1 must always run the same thing), though old ones may be dropped.
func transition(old, next meta.Object) []string {
	var errs []string
	if o, ok := old.(*v1.Image); ok {
		n := next.(*v1.Image)
		for _, ov := range o.Spec.Versions {
			for _, nv := range n.Spec.Versions {
				if nv.Name == ov.Name && !reflect.DeepEqual(nv, ov) {
					errs = append(errs, fmt.Sprintf("version %s can't change once added: add a new version instead", ov.Name))
				}
			}
		}
	}
	return errs
}
