// Package internalca is the built-in "internal-ca" cert-controller: certificates from the cluster's
// own CA, for private hosts (api.payments.kevaso, a LAN name). No challenge: the cluster vouches
// for its own names.
package internalca

import (
	"context"

	"kevaso.com/core/sdk/kcc"
)

// Sign signs a CSR (DER) as a server certificate for hosts, returning the chain (DER, leaf first).
// The control plane gives it its CA.
type Sign func(csr []byte, hosts []string) ([][]byte, error)

// Controller is the internal-ca cert-controller.
type Controller struct{ Sign Sign }

// Info implements kcc.CertController.
func (c *Controller) Info() kcc.Info {
	return kcc.Info{Name: "internal-ca", Description: "the cluster's own CA, for private hosts"}
}

// Issue implements kcc.CertController.
func (c *Controller) Issue(_ context.Context, r kcc.Request) ([][]byte, error) {
	return c.Sign(r.CSR, r.Hosts)
}

var _ kcc.CertController = (*Controller)(nil)
