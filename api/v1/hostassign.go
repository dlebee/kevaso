package v1

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// hostLabel is one DNS label: a letter or digit, then letters, digits or hyphens, not ending in a hyphen.
var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// HostAssignment gives a host name (api.example.com) or a one-label suffix (*.shop.example.com)
// to the namespaces that may publish it. A host with no assignment cannot be claimed. Only a
// cluster admin writes an IngressClass, which is where the assignment lives.
type HostAssignment struct {
	Host       string   `json:"host"`
	Namespaces []string `json:"namespaces"`
}

// NormalizeDNS is a host name in the form assignments and routes compare: lower case, no
// trailing dot.
func NormalizeDNS(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// ValidHostPattern reports whether p is a host name or a one-label suffix (*.example.com).
func ValidHostPattern(p string) bool {
	p = NormalizeDNS(p)
	if rest, ok := strings.CutPrefix(p, "*."); ok {
		if rest == "" {
			return false
		}
		p = rest
	}
	if p == "" || strings.Contains(p, "*") || net.ParseIP(p) != nil {
		return false
	}
	for _, l := range strings.Split(p, ".") {
		if len(l) == 0 || len(l) > 63 || !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// HostMatches reports whether host is pattern: the same name, or exactly one label under a
// *.suffix pattern. *.shop.example.com matches a.shop.example.com and not shop.example.com or
// b.a.shop.example.com.
func HostMatches(pattern, host string) bool {
	pattern, host = NormalizeDNS(pattern), NormalizeDNS(host)
	if pattern == "" || host == "" {
		return false
	}
	if pattern == host {
		return true
	}
	suffix, ok := strings.CutPrefix(pattern, "*.")
	if !ok || suffix == "" || strings.Contains(suffix, "*") {
		return false
	}
	label, rest, ok := strings.Cut(host, ".")
	return ok && label != "" && !strings.Contains(label, ".") && rest == suffix
}

// Allows reports whether this assignment lets namespace publish host.
func (a HostAssignment) Allows(namespace, host string) bool {
	if namespace == "" || !HostMatches(a.Host, host) {
		return false
	}
	for _, ns := range a.Namespaces {
		if ns == namespace {
			return true
		}
	}
	return false
}

// AllowsHost reports whether the class assigns host to namespace.
func (c *IngressClass) AllowsHost(namespace, host string) bool {
	if c == nil || c.DeletionTimestamp != nil {
		return false
	}
	for _, a := range c.Spec.Hosts {
		if a.Allows(namespace, host) { // only an assignment grants the host
			return true
		}
	}
	return false // no assignment grants this host to the namespace
}

// InternalServiceHost reports whether host is a service name of namespace: SERVICE.NAMESPACE.SUFFIX
// or SERVICE.NAMESPACE.NETWORK.SUFFIX (mesh, internal, external). Another namespace's name is not.
func InternalServiceHost(host, namespace, suffix string) bool {
	host = NormalizeDNS(host)
	if suffix == "" {
		suffix = DefaultSuffix
	}
	suffix = NormalizeDNS(suffix)
	rest, ok := strings.CutSuffix(host, "."+suffix)
	if !ok || namespace == "" {
		return false
	}
	parts := strings.Split(rest, ".")
	switch len(parts) {
	case 2:
		if parts[1] != namespace { // a service name is only the namespace's own
			return false
		}
		return parts[0] != "" && hostLabel.MatchString(parts[0])
	case 3:
		if parts[1] != namespace || !isNetworkLabel(parts[2]) {
			return false
		}
		return parts[0] != "" && hostLabel.MatchString(parts[0])
	default:
		return false
	}
}

func isNetworkLabel(s string) bool {
	for _, n := range Networks {
		if s == n {
			return true
		}
	}
	return false
}

// IsAPIName reports whether host is one of the API server's names (a DNS name or an address).
func IsAPIName(host string, names []string) bool {
	host = normalizeAPIName(host)
	if host == "" {
		return false
	}
	for _, n := range names {
		if normalizeAPIName(n) == host {
			return true
		}
	}
	return false
}

func normalizeAPIName(n string) string {
	n = NormalizeDNS(n)
	if ip := net.ParseIP(n); ip != nil {
		return ip.String()
	}
	return n
}

// HostAPINames are the names of h that clients can use for an API on it: its name, its addresses,
// and the host of its API URL.
func HostAPINames(h *Host) []string {
	if h == nil {
		return nil
	}
	var out []string
	if h.Name != "" {
		out = append(out, h.Name)
	}
	if ip := h.Internal(); ip != "" {
		out = append(out, ip)
	}
	if ip := h.External(); ip != "" {
		out = append(out, ip)
	}
	if cp := h.Status.ControlPlane; cp != nil && cp.APIURL != "" {
		if u, err := url.Parse(cp.APIURL); err == nil && u.Hostname() != "" {
			out = append(out, u.Hostname())
		}
	}
	return out
}

// APINameProblem is why host must not be signed: it is a name of the API server. Empty if it isn't.
func APINameProblem(host string, names []string) string {
	if IsAPIName(host, names) { // an API server name is never signed
		return fmt.Sprintf("host %q is a name of this cluster's API server and is not signed", NormalizeDNS(host))
	}
	return ""
}

// IngressHostProblem is why namespace may not publish host on class. Empty if it may.
func IngressHostProblem(host, namespace string, class *IngressClass, apiNames []string) string {
	if why := APINameProblem(host, apiNames); why != "" {
		return why
	}
	if class != nil && class.AllowsHost(namespace, host) {
		return ""
	}
	name := ""
	if class != nil {
		name = class.Name
	}
	shown := NormalizeDNS(host)
	className := name
	if className == "" {
		className = "CLASS"
	}
	return fmt.Sprintf("host %q is not assigned to namespace %s on ingress class %s: set IngressClass.spec.hosts, or add one with: kvoadm ingress assign %s --host %s=%s",
		shown, namespace, name, className, shown, namespace)
}

// CertificateHostProblem is why namespace may not have a certificate for host: it is an API server
// name, or it is neither assigned to the namespace on an IngressClass nor one of the namespace's
// own service names. Empty if it may.
func CertificateHostProblem(host, namespace, suffix string, classes []*IngressClass, apiNames []string) string {
	if why := APINameProblem(host, apiNames); why != "" {
		return why
	}
	if InternalServiceHost(host, namespace, suffix) {
		return ""
	}
	for _, c := range classes {
		if c != nil && c.AllowsHost(namespace, host) {
			return ""
		}
	}
	if suffix == "" {
		suffix = DefaultSuffix
	}
	return fmt.Sprintf("host %q is not assigned to namespace %s on an ingress class, and is not one of its service names (NAME.%s.%s): ask a cluster admin to assign it",
		NormalizeDNS(host), namespace, namespace, NormalizeDNS(suffix))
}
