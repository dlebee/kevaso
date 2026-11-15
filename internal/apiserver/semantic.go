package apiserver

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ips"
	"kevaso.com/core/internal/names"
	"kevaso.com/core/internal/probes"
)

// semantic checks what CEL can't say well: addresses and ranges.
func semantic(obj meta.Object) []string {
	var errs []string
	switch o := obj.(type) {
	case *v1.Silo:
		errs = append(errs, checkPorts(o.Spec)...)
		for _, u := range o.Spec.Upkeep {
			if d, err := time.ParseDuration(u.Every); err != nil || d < time.Minute {
				errs = append(errs, fmt.Sprintf("upkeep %s: every %q: want a duration of at least 1m (e.g. 6h)", u.Name, u.Every))
			}
		}
		errs = append(errs, probes.Validate(o.Spec)...)
		errs = append(errs, o.Spec.Availability.ControlPlaneLossProblems()...)
	case *v1.Service:
		for _, p := range o.Spec.Ports {
			if t := p.TargetPort; t != "" && !label.MatchString(t) {
				errs = append(errs, fmt.Sprintf("port %s: targetPort %q: the name of a port the silos declare (spec.ports)", p.Name, t))
			}
		}
	case *v1.Namespace:
		if names.Reserved(o.Name) {
			errs = append(errs, fmt.Sprintf("%q is a network's name (mesh, internal, external), which names use as a label of their own: pick another", o.Name))
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
			if sec.Path != "" && (!strings.HasPrefix(sec.Path, "/run/") || !v1.CleanMountPath(sec.Path)) {
				errs = append(errs, fmt.Sprintf("secret %s: path %q must be under /run/ (tmpfs: a secret file never reaches the silo's disk), a clean path of letters, digits, . _ - and /", sec.Name, sec.Path))
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
			if ad, err := netip.ParseAddr(a); err != nil {
				errs = append(errs, fmt.Sprintf("spec.address: %q isn't an address", a))
			} else if !ad.Is4() {
				errs = append(errs, fmt.Sprintf("spec.address: %q: IPv6 comes later; IPv4 for now", a))
			}
		}
	case *v1.Host:
		for _, f := range []struct{ field, v string }{{"spec.internalIP", o.Spec.InternalIP}, {"spec.externalIP", o.Spec.ExternalIP}} {
			if a, err := netip.ParseAddr(f.v); f.v != "" && (err != nil || !a.Is4()) {
				errs = append(errs, fmt.Sprintf("%s: %q isn't an IPv4 address", f.field, f.v))
			}
		}
		if o.Spec.InternalIP != "" && o.Spec.InternalIP == o.Spec.ExternalIP {
			errs = append(errs, "spec.internalIP and spec.externalIP are the same address: a machine with one address has one of the two (external if it's reachable from outside its network)")
		}
		for _, n := range o.Spec.Network.DNS {
			switch {
			case n != v1.NetworkInternal && n != v1.NetworkExternal:
				errs = append(errs, fmt.Sprintf("spec.network.dns: %q: internal or external (silos and the mesh are always answered)", n))
			case n == v1.NetworkExternal && o.Spec.ExternalIP == "":
				errs = append(errs, fmt.Sprintf("spec.network.dns: %s: the host has no %s IP", n, n))
			}
		}
		for _, a := range o.Spec.Network.Addresses {
			if _, err := ips.Parse(a); err != nil {
				errs = append(errs, "spec.network.addresses: "+err.Error())
			}
		}
	}
	return errs
}

// normalize writes what users give for the firewall in its one form, before it is checked and
// stored: a port's sources (silo, and a SiloSet's template) and the CIDRs of a Grant's egress.
// Entries that don't parse are left for semantic to refuse.
func normalize(obj meta.Object) {
	ports := func(sv *v1.SiloService) {
		if sv == nil {
			return
		}
		for i := range sv.Ports {
			if len(sv.Ports[i].Sources) > 0 {
				sv.Ports[i].Sources = v1.NormalizeSources(sv.Ports[i].Sources)
			}
		}
	}
	switch o := obj.(type) {
	case *v1.Silo:
		ports(o.Spec.Service)
	case *v1.SiloSet:
		ports(o.Spec.Template.Service)
	case *v1.Grant:
		for i, r := range o.Spec.Egress {
			if e, err := r.Parse(); err == nil && e.Prefix.IsValid() {
				if e.Prefix.Bits() == 32 {
					o.Spec.Egress[i].To = e.Prefix.Addr().String()
				} else {
					o.Spec.Egress[i].To = e.Prefix.String()
				}
			}
		}
	}
}

// transition checks what may change on an update: a VMImage's versions are immutable once added
// (an instance on v1 must always run the same thing), though old ones may be dropped.
func transition(old, next meta.Object) []string {
	var errs []string
	if o, ok := old.(*v1.IP); ok {
		errs = append(errs, ipTransition(o, next.(*v1.IP))...)
	}
	if o, ok := old.(*v1.VMImage); ok {
		n := next.(*v1.VMImage)
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
