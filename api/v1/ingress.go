package v1

import (
	"encoding/json"
	"time"

	"kevaso.com/core/api/meta"
)

// Ingress (design §7.3): HTTP(S) from outside to private silos, by host name and path, through an
// ingress controller that is an ordinary silo. Certificates are automated, cert-manager style: an
// Ingress names the Issuer its certificate comes from (or gets the cluster's default for its class:
// letsencrypt on public classes, internal-ca on private ones), and a Certificate is made for it,
// whose certificate and key land in a Secret, renewed before they expire.

// IngressClass is a set of ingress controllers: which silo serves Ingresses of this class. Cluster
// scope.
type IngressClass struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            IngressClassSpec `json:"spec"`
}

// IngressClassSpec is the class's controller and what it means to publish on it.
type IngressClassSpec struct {
	Controller SiloRef `json:"controller"`
	// Public: reachable from the internet. Publishing an Ingress on a public class needs create on
	// ingresses/publish-public in its namespace.
	Public bool `json:"public,omitempty"`
	// DNS, when set, publishes every Ingress host name of this class through a DNS provider,
	// pointing at the controller's public address.
	DNS *IngressDNS `json:"dns,omitempty"`
}

// IngressDNS is the DNS provider an IngressClass publishes host names with.
type IngressDNS struct {
	Provider string `json:"provider"`      // a DNS provider name, e.g. linode
	TTL      int    `json:"ttl,omitempty"` // seconds (default 300)
}

// SiloRef names a silo in a namespace.
type SiloRef struct {
	Silo      string `json:"silo"`
	Namespace string `json:"namespace"`
}

// Ingress routes HTTP(S) for some host names to silos. Namespaced.
type Ingress struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            IngressSpec   `json:"spec"`
	Status          IngressStatus `json:"status,omitempty"`
}

// IngressSpec is the routing.
type IngressSpec struct {
	IngressClass string        `json:"ingressClass"`
	Hosts        []string      `json:"hosts"`
	TLS          IngressTLS    `json:"tls,omitempty"`
	Rules        []IngressRule `json:"rules"`
}

// IngressTLS says where the certificate comes from; at most one is set. None of them: a
// certificate from the cluster's default issuer for the class (letsencrypt on public classes,
// internal-ca on private ones).
type IngressTLS struct {
	// Issuer is the Issuer its certificate comes from (any: acme, internal-ca, a cert-controller's).
	Issuer string `json:"issuer,omitempty"`
	// SecretName uses a certificate you keep yourself, in this Secret of the namespace (the chain
	// and key, PEM): no Certificate is made.
	SecretName string `json:"secretName,omitempty"`
	// None is plain HTTP, on private classes only.
	None bool `json:"none,omitempty"`
}

// TLSSecret is the Secret an Ingress's certificate is in: its own, or the one made for it.
func TLSSecret(ing *Ingress) string {
	if ing.Spec.TLS.SecretName != "" {
		return ing.Spec.TLS.SecretName
	}
	return CertificateFor(ing)
}

// IngressRule sends a path (prefix) to a silo's port, in the Ingress's namespace.
type IngressRule struct {
	Path string        `json:"path,omitempty"` // prefix, default /
	Silo IngressTarget `json:"silo"`
}

// IngressTarget is a silo and one of its service ports (by name).
type IngressTarget struct {
	Name string `json:"name"`
	Port string `json:"port"`
}

// IngressStatus is what the platform reports.
type IngressStatus struct {
	Address     string           `json:"address,omitempty"`     // where the hosts should point (the controller's public IP)
	Certificate string           `json:"certificate,omitempty"` // the Certificate made for it
	DNSNames    []string         `json:"dnsNames,omitempty"`    // the host names published through the class's DNS provider
	Conditions  []meta.Condition `json:"conditions,omitempty"`
}

// Issuer is where certificates come from. Cluster scope.
type Issuer struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            IssuerSpec `json:"spec"`
}

// IssuerSpec says which cert-controller issues certificates, and its settings: spec.controller with
// spec.config, or the shorthands acme (controller "acme") and internalCA (controller "internal-ca").
type IssuerSpec struct {
	Controller string          `json:"controller,omitempty"`
	Config     json.RawMessage `json:"config,omitempty"`
	ACME       *ACMEIssuer     `json:"acme,omitempty"`
	InternalCA bool            `json:"internalCA,omitempty"`
}

// CertController is the cert-controller an Issuer uses and its configuration.
func (i *Issuer) CertController() (string, json.RawMessage) {
	switch {
	case i.Spec.Controller != "":
		return i.Spec.Controller, i.Spec.Config
	case i.Spec.ACME != nil:
		b, _ := json.Marshal(i.Spec.ACME)
		return "acme", b
	case i.Spec.InternalCA:
		return "internal-ca", nil
	}
	return "", nil
}

// ACMEIssuer is an ACME server (Let's Encrypt, or a private one).
type ACMEIssuer struct {
	Server string `json:"server"` // directory URL
	Email  string `json:"email,omitempty"`
	// ServerCA is a PEM CA to trust for the ACME server itself (a private ACME server; Let's
	// Encrypt needs none).
	ServerCA string `json:"serverCA,omitempty"`
	// Solvers say how each host is proven: the most specific selector wins (dnsNames, then the
	// longest dnsZones match, then a solver without a selector). Default: http01 for every host.
	Solvers []ACMESolver `json:"solvers,omitempty"`
}

// ACMESolver is one way of answering ACME challenges, for the hosts its selector matches.
type ACMESolver struct {
	Selector *ACMESelector `json:"selector,omitempty"`
	HTTP01   *ACMEHTTP01   `json:"http01,omitempty"`
	DNS01    *ACMEDNS01    `json:"dns01,omitempty"`
}

// ACMESelector picks hosts: exact names, or every name in (or under) a zone.
type ACMESelector struct {
	DNSNames []string `json:"dnsNames,omitempty"`
	DNSZones []string `json:"dnsZones,omitempty"`
}

// ACMEHTTP01 answers on port 80 through the cluster's ingress controllers.
type ACMEHTTP01 struct{}

// ACMEDNS01 answers with a TXT record at _acme-challenge.<host>, written by a DNS provider
// registered on the control-plane host (kevasod control-plane --dns-provider NAME=PROGRAM).
type ACMEDNS01 struct {
	Provider           string `json:"provider"`
	PropagationSeconds int    `json:"propagationSeconds,omitempty"` // wait before the server checks (default 60)
}

// Let's Encrypt's directory URLs.
const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Certificate asks for a certificate for some hosts from an Issuer; the certificate and its key go
// to a Secret (PEM: certificate chain, then key), renewed automatically. Namespaced.
type Certificate struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            CertificateSpec   `json:"spec"`
	Status          CertificateStatus `json:"status,omitempty"`
}

// CertificateSpec is what to get, from where, and where to put it.
type CertificateSpec struct {
	Hosts      []string `json:"hosts"`
	Issuer     string   `json:"issuer"`
	SecretName string   `json:"secretName"`
}

// CertificateStatus is its current certificate's validity and how getting it went.
type CertificateStatus struct {
	NotBefore  *time.Time `json:"notBefore,omitempty"`
	NotAfter   *time.Time `json:"notAfter,omitempty"`
	RenewAfter *time.Time `json:"renewAfter,omitempty"`
	Serial     string     `json:"serial,omitempty"`
	// FailedAttempts and NextAttempt: after a failure, the next try waits 1 minute, doubling up to
	// an hour, so a broken setup doesn't hammer the CA (Let's Encrypt rate-limits).
	FailedAttempts int              `json:"failedAttempts,omitempty"`
	NextAttempt    *time.Time       `json:"nextAttempt,omitempty"`
	Conditions     []meta.Condition `json:"conditions,omitempty"`
}

// CertificateFor is the name of the Certificate an Ingress gets.
func CertificateFor(ing *Ingress) string { return ing.Name + "-tls" }
