package integration

import "testing"

// IP objects in a real control plane with the fake plugin (design §7.2c-1, §7.2b): an IP made by
// hand is reserved before any service, a silo's service takes it, the silo goes and the address
// stays, a new silo takes the same address; an IP someone holds can't be deleted or taken; a
// host's extra address can't be taken from the host while an IP holds it.
func TestIPs(t *testing.T) {
	t.Skip("TODO(net-v2 wave 2): IPs held by services (Provider IPs on a balancer, Host IPs on a HostPort service), the address kept across silos, held IPs undeletable, host addresses in use kept")
}
