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
	"kevaso.com/core/internal/ips"
	"kevaso.com/core/internal/probes"
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
		for _, u := range o.Spec.Upkeep {
			if d, err := time.ParseDuration(u.Every); err != nil || d < time.Minute {
				errs = append(errs, fmt.Sprintf("upkeep %s: every %q: want a duration of at least 1m (e.g. 6h)", u.Name, u.Every))
			}
		}
		for _, a := range o.Spec.AllowFrom {
			if strings.Count(a.Silo, "/") > 1 {
				errs = append(errs, fmt.Sprintf("allowFrom: %q: want NAME or NAMESPACE/NAME", a.Silo))
			}
		}
		errs = append(errs, probes.Validate(o.Spec)...)
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
	case *v1.IP:
		if a := o.Spec.Address; a != "" {
			if _, err := netip.ParseAddr(a); err != nil {
				errs = append(errs, fmt.Sprintf("spec.address: %q isn't an address", a))
			}
		}
	case *v1.Host:
		for _, a := range o.Spec.Network.Addresses {
			if _, err := ips.Parse(a); err != nil {
				errs = append(errs, "spec.network.addresses: "+err.Error())
			}
		}
	}
	return errs
}

// transition checks what may change on an update: an Image's versions are immutable once added
// (an instance on v1 must always run the same thing), though old ones may be dropped.
func transition(old, next meta.Object) []string {
	var errs []string
	if o, ok := old.(*v1.IP); ok {
		errs = append(errs, ipTransition(o, next.(*v1.IP))...)
	}
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
