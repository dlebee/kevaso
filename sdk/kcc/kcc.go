// Package kcc is the cert-controller interface: how Kevaso gets a certificate, from anywhere, behind
// one small interface (next to the runtime, network and KMS interfaces).
//
// Kevaso keeps the lifecycle: which certificates must exist, when to issue and renew them, and where
// they're stored (sealed Secrets). A cert-controller does one thing: turn a CSR for some hosts into a
// certificate chain. How it does that is its own business: an ACME client with challenge solvers, a
// private CA, a wrapped tool like certbot, a cloud CA's API. Kevaso makes the private key and sends
// only the CSR, so a cert-controller never sees a certificate's key.
//
// An Issuer names its cert-controller (spec.controller) and gives it its settings (spec.config).
package kcc

import (
	"context"
	"encoding/json"
	"errors"
)

// Info describes a cert-controller.
type Info struct {
	Name        string
	Description string
}

// Request is one certificate to issue.
type Request struct {
	Issuer string          // the Issuer's name
	Config json.RawMessage // the Issuer's settings for this cert-controller
	Hosts  []string
	CSR    []byte // DER
}

// CertController issues certificates.
type CertController interface {
	Info() Info
	// Issue returns the certificate chain (DER, leaf first) for the request's CSR.
	Issue(ctx context.Context, r Request) ([][]byte, error)
}

// Registry is the cert-controllers a control plane knows, by name.
type Registry map[string]CertController

// Get returns the named cert-controller.
func (r Registry) Get(name string) (CertController, error) {
	if c, ok := r[name]; ok {
		return c, nil
	}
	return nil, errors.New("kcc: no cert-controller named " + name)
}
