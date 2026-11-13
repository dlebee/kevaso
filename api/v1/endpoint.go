package v1

// The local endpoint (design §8.2, ADR 0008): a plain HTTP endpoint every silo on the bridge
// reaches at the same link-local address, answered by its own host, for what the silo asks for
// itself: a broker secret, a signature or a public key, a port lease. Who is asking is where the
// request arrived (its source address on the bridge, which a silo can't fake), never anything in
// the request.
const (
	// EndpointAddress is where every silo reaches its host's endpoint (a /32 on the silo bridge).
	// Not 169.254.169.254: clouds use that for their own metadata, which the host may need.
	EndpointAddress = "169.254.42.1"
	EndpointPort    = 80
	// EndpointHeader must be on every request, with the value "1": a browser can't send it without a
	// CORS preflight (refused), and a URL some program is tricked into fetching doesn't carry it.
	EndpointHeader = "Kevaso-Local"
)

// NeedsEndpoint reports whether a silo has anything to ask its endpoint for: a broker secret, a
// signing key or a leased port. A silo that doesn't has no endpoint at all. Pure.
func NeedsEndpoint(s *Silo, grants []*Grant) bool {
	if s.Spec.Service != nil && s.Spec.Service.Lease != nil {
		return true
	}
	for _, g := range GrantsFor(s, grants) {
		if g.Spec.Operations != nil && g.Spec.Operations.Sign != nil {
			return true
		}
		for _, gs := range g.Spec.Secrets {
			if gs.Delivery() == DeliverBroker {
				return true
			}
		}
	}
	return false
}

// HostWrites reports whether the host writes secrets into the silo (file or env deliveries). Pure.
func HostWrites(s *Silo, grants []*Grant) bool {
	for _, g := range GrantsFor(s, grants) {
		for _, gs := range g.Spec.Secrets {
			if d := gs.Delivery(); d == DeliverFile || d == DeliverEnv {
				return true
			}
		}
	}
	return false
}

// Injects reports whether one of the silo's grants injects a secret (so it must trust its host's
// egress CA). Pure.
func Injects(s *Silo, grants []*Grant) bool {
	for _, g := range GrantsFor(s, grants) {
		for _, gs := range g.Spec.Secrets {
			if gs.Delivery() == DeliverInject {
				return true
			}
		}
	}
	return false
}
