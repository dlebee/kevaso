package apiserver

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ips"
	"kevaso.com/core/internal/names"
	"kevaso.com/core/internal/policy"
	"kevaso.com/core/internal/probes"
)

// hostAssignNS is a namespace name on a host assignment.
var hostAssignNS = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

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
		if len(o.Spec.OpenShellPolicies) > 0 && !policy.SelfEnforced(o.Spec.Runtime) { // openshellPolicies only on an openshell runtime
			errs = append(errs, fmt.Sprintf("openshellPolicies is only for runtime openshell or openshell-container; %s can't use one", o.Spec.Runtime))
		}
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
			e, err := r.Parse()
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			// The cluster's ranges, loopback, link-local, this-network, multicast and reserved are never opened through the gate.
			if pfx, why := v1.ClosedRange(e.Prefix); why != "" {
				errs = append(errs, fmt.Sprintf("egress %q is inside %s (%s), which a grant never opens", r.To, pfx, why))
			}
		}
		for _, sec := range o.Spec.Secrets {
			switch {
			case sec.Delivery() == v1.DeliverSign:
				if sec.Key != "" {
					errs = append(errs, fmt.Sprintf("secret %s: a signing key has no keys to name", sec.Name))
				}
			case sec.KeyRefProblem() != "":
				errs = append(errs, fmt.Sprintf("secret %s: %s", sec.Name, sec.KeyRefProblem()))
			}
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
	case *v1.IngressClass:
		seen := map[string]bool{}
		for _, a := range o.Spec.Hosts {
			if !v1.ValidHostPattern(a.Host) {
				errs = append(errs, fmt.Sprintf("spec.hosts: %q isn't a host name or a suffix (*.example.com)", a.Host))
				continue
			}
			key := v1.NormalizeDNS(a.Host)
			if seen[key] {
				errs = append(errs, fmt.Sprintf("spec.hosts: %q is listed twice", a.Host))
			}
			seen[key] = true
			if len(a.Namespaces) == 0 {
				errs = append(errs, fmt.Sprintf("spec.hosts: %q needs the namespaces allowed to use it", a.Host))
			}
			for _, ns := range a.Namespaces {
				if !hostAssignNS.MatchString(ns) {
					errs = append(errs, fmt.Sprintf("spec.hosts: namespace %q isn't a name", ns))
				}
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
		for _, k := range o.Spec.RemoveKeys {
			if !v1.ValidKey(k) {
				errs = append(errs, fmt.Sprintf("spec.removeKeys: %q isn't a key's name", k))
			}
		}
	case *v1.IP:
		if a := o.Spec.Address; a != "" {
			if ad, err := netip.ParseAddr(a); err != nil {
				errs = append(errs, fmt.Sprintf("spec.address: %q isn't an address", a))
			} else if !ad.Is4() {
				errs = append(errs, fmt.Sprintf("spec.address: %q: IPv6 comes later; IPv4 for now", a))
			}
		}
	case *v1.OpenShellPolicy:
		errs = append(errs, openShellPolicyProblems(o)...)
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
	case *v1.OpenShellPolicy:
		for i := range o.Spec.NetworkPolicies {
			for j := range o.Spec.NetworkPolicies[i].Endpoints {
				h := o.Spec.NetworkPolicies[i].Endpoints[j].Host
				if canon, err := v1.OpenShellHost(h); err == nil {
					o.Spec.NetworkPolicies[i].Endpoints[j].Host = canon
				}
			}
		}
	}
}

// openShellPolicyProblems checks hosts and paths, which CEL does not.
func openShellPolicyProblems(o *v1.OpenShellPolicy) []string {
	var errs []string
	for _, rule := range o.Spec.NetworkPolicies {
		for _, e := range rule.Endpoints {
			if _, err := v1.OpenShellHost(e.Host); err != nil && e.Host != "" {
				errs = append(errs, err.Error())
			}
			if e.Path != "" && !v1.OpenShellPath(e.Path) {
				errs = append(errs, fmt.Sprintf("path %q: an absolute path glob (starts with /), no control character or .. segment, at most 200 characters", e.Path))
			}
		}
		if rule.Binaries != nil && len(rule.Binaries) == 0 {
			// An omitted list is nil (every binary). An empty list is set, and a rule with no
			// binary allows nothing, so it is refused rather than stored as "every binary".
			errs = append(errs, "binaries, when set, are 1 to 16 paths")
		}
		for _, b := range rule.Binaries {
			if b.Path != "" && !v1.OpenShellPath(b.Path) {
				errs = append(errs, fmt.Sprintf("binaries path %q: an absolute path (starts with /), no control character or .. segment, at most 200 characters", b.Path))
			}
		}
	}
	return errs
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
	errs = append(errs, volumeClassChanges(old, next)...)
	return errs
}

// volumeClassChanges refuses a new class for a volume name, or for spec.disk.class, that the
// silo already has. A name kept in status (taken out of the spec, or not yet marked kept) is
// the same: it cannot come back under another class. Empty and local are the same class.
// Taking a name out of the spec is not a class change: the volume stays until the silo is deleted.
func volumeClassChanges(old, next meta.Object) []string {
	var a, b v1.SiloSpec
	var kept []v1.VolumeStatus
	switch o := old.(type) {
	case *v1.Silo:
		a, b = o.Spec, next.(*v1.Silo).Spec
		kept = o.Status.Volumes
	case *v1.SiloSet:
		a, b = o.Spec.Template.SiloSpec, next.(*v1.SiloSet).Spec.Template.SiloSpec
	default:
		return nil
	}
	return classChanges(a, b, kept)
}

func classChanges(old, next v1.SiloSpec, kept []v1.VolumeStatus) []string {
	was := map[string]string{}
	for _, v := range old.Volumes {
		was[v.Name] = volumeClass(v.Class)
	}
	for _, v := range kept {
		if _, seen := was[v.Name]; !seen && v.Name != "" {
			was[v.Name] = volumeClass(v.Class)
		}
	}
	var errs []string
	for _, v := range next.Volumes {
		if prev, ok := was[v.Name]; ok && prev != volumeClass(v.Class) {
			errs = append(errs, fmt.Sprintf("volume %s: class can't change in place (%s to %s); delete the silo to drop the volume", v.Name, prev, volumeClass(v.Class)))
		}
	}
	if old.Runtime == "cloud-hypervisor" && next.Runtime == "cloud-hypervisor" && volumeClass(old.Disk.Class) != volumeClass(next.Disk.Class) {
		errs = append(errs, fmt.Sprintf("disk.class can't change in place (%s to %s); delete the silo to drop the disk", volumeClass(old.Disk.Class), volumeClass(next.Disk.Class)))
	}
	return errs
}

func volumeClass(c string) string {
	if c == "" || c == v1.VolumeLocal {
		return v1.VolumeLocal
	}
	return c
}
