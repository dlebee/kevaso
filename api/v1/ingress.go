package v1

import (
	"time"

	"kevaso.com/core/api/meta"
)

// Ingress (design §7.3): HTTP(S) from outside to private silos, by host name and path, through an
// ingress controller that is an ordinary silo. Certificates are automated, cert-manager style:
// an Ingress with tls.mode acme gets a Certificate, whose certificate and key land in a Secret,
// renewed before they expire.

// TLS modes of an Ingress.
const (
	TLSAcme       = "acme"        // a certificate from the class's ACME issuer (HTTP-01)
	TLSInternalCA = "internal-ca" // a certificate from the cluster's own CA (private hosts)
	TLSNone       = "none"        // plain HTTP (private classes only)
)

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
	// Issuer is the Issuer certificates for tls.mode acme come from (default: letsencrypt).
	Issuer string `json:"issuer,omitempty"`
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

// IngressTLS says where the certificate comes from.
type IngressTLS struct {
	Mode string `json:"mode,omitempty"` // acme (default on public classes) | internal-ca | none
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
	Conditions  []meta.Condition `json:"conditions,omitempty"`
}

// Issuer is where certificates come from. Cluster scope.
type Issuer struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            IssuerSpec `json:"spec"`
}

// IssuerSpec is one of ACME or the cluster's own CA.
type IssuerSpec struct {
	ACME       *ACMEIssuer `json:"acme,omitempty"`
	InternalCA bool        `json:"internalCA,omitempty"`
}

// ACMEIssuer is an ACME server (Let's Encrypt, or a private one).
type ACMEIssuer struct {
	Server string `json:"server"` // directory URL
	Email  string `json:"email,omitempty"`
	// ServerCA is a PEM CA to trust for the ACME server itself (a private ACME server; Let's
	// Encrypt needs none).
	ServerCA string `json:"serverCA,omitempty"`
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
	NotBefore  *time.Time       `json:"notBefore,omitempty"`
	NotAfter   *time.Time       `json:"notAfter,omitempty"`
	RenewAfter *time.Time       `json:"renewAfter,omitempty"`
	Serial     string           `json:"serial,omitempty"`
	Conditions []meta.Condition `json:"conditions,omitempty"`
}

// CertificateFor is the name of the Certificate an Ingress gets.
func CertificateFor(ing *Ingress) string { return ing.Name + "-tls" }
