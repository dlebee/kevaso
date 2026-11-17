package v1

import (
	"fmt"
	"net/netip"
	"strings"

	"kevaso.com/core/api/meta"
)

// How long an OpenShellPolicy's lists may be. A grant rendered for OpenShell already lists at
// most 16 destinations (internal/policy maxPolicyPorts); a rule here has the same bound on
// endpoints and on binaries. A policy holds at most 32 rules, and a silo names at most 32 policies.
const (
	MaxOpenShellRules       = 32
	MaxOpenShellEndpoints   = 16
	MaxOpenShellBinaries    = 16
	MaxOpenShellPolicyNames = 32
)

// OpenShellPolicy is extra egress for an OpenShell sandbox: path, access, protocol and which
// binaries may use a rule. Namespaced. A Grant stays host and port; this is what OpenShell's own
// network_policies can say that a Grant cannot.
type OpenShellPolicy struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            OpenShellPolicySpec `json:"spec"`
}

// OpenShellPolicySpec is the policy's rules, in order.
type OpenShellPolicySpec struct {
	NetworkPolicies []OpenShellNetworkPolicy `json:"networkPolicies,omitempty"`
}

// OpenShellNetworkPolicy is one OpenShell network rule.
type OpenShellNetworkPolicy struct {
	Name      string              `json:"name"`
	Endpoints []OpenShellEndpoint `json:"endpoints,omitempty"`
	Binaries  []OpenShellBinary   `json:"binaries,omitempty"` // empty: every binary
}

// OpenShellEndpoint is one destination. Protocol, path and access are optional; OpenShell's
// policy file omits a field that is empty.
type OpenShellEndpoint struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"` // rest
	Path     string `json:"path,omitempty"`     // absolute glob
	Access   string `json:"access,omitempty"`   // read-only | read-write
}

// OpenShellBinary is a program that may use the rule. Omitted binaries means every program.
type OpenShellBinary struct {
	Path string `json:"path"`
}

// Access values OpenShell writes on a network endpoint.
const (
	AccessReadOnly  = "read-only"
	AccessReadWrite = "read-write"
)

// PoliciesFor returns the OpenShell policies a silo lists that exist, in its namespace, in the
// silo's order. A name with no object is skipped, as GrantsFor skips a missing grant.
func PoliciesFor(s *Silo, all []*OpenShellPolicy) []*OpenShellPolicy {
	var out []*OpenShellPolicy
	for _, name := range s.Spec.OpenShellPolicies {
		for _, p := range all {
			if p.Namespace == s.Namespace && p.Name == name {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// OpenShellHost checks an endpoint host and returns it in the form that is stored: a lower-case
// name, or one public IPv4 address. An address or CIDR inside a closed range is refused with an
// error that names the range. A wider range, a private address, and anything that is not a name
// or one public address is refused too.
func OpenShellHost(host string) (string, error) {
	raw := strings.TrimSpace(host)
	if raw == "" {
		return "", fmt.Errorf("endpoint host is required")
	}
	if p, err := netip.ParsePrefix(raw); err == nil {
		return openShellIP(p.Addr(), p.Bits(), raw)
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		return openShellIP(a, a.BitLen(), raw)
	}
	h := strings.ToLower(strings.TrimSuffix(raw, "."))
	if !validHostPattern(h) {
		return "", fmt.Errorf("endpoint host %q: not a host name or a public address", raw)
	}
	return h, nil
}

func openShellIP(a netip.Addr, bits int, raw string) (string, error) {
	a = a.Unmap()
	if bits < 0 || bits > a.BitLen() {
		bits = a.BitLen()
	}
	pfx := netip.PrefixFrom(a, bits).Masked()
	if closed, why := ClosedRange(pfx); why != "" { // an OpenShellPolicy never opens a closed range
		return "", fmt.Errorf("endpoint host %q is inside %s (%s), which a policy never opens", raw, closed, why)
	}
	if !a.Is4() {
		return "", fmt.Errorf("endpoint host %q: IPv6 comes later; IPv4 for now", raw)
	}
	if bits != a.BitLen() {
		return "", fmt.Errorf("endpoint host %q: a host is a name or one public address, not a range", raw)
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
		return "", fmt.Errorf("endpoint host %q: hosts are names or public addresses", raw)
	}
	return a.String(), nil
}

// OpenShellPath reports whether p is an absolute path glob OpenShell can take: it starts with /,
// has no control character and no ".." segment, and is at most 200 characters. Empty is not a path.
func OpenShellPath(p string) bool {
	if p == "" || len(p) > 200 || !strings.HasPrefix(p, "/") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r > 0x7e {
			return false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}
