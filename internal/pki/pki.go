// Package pki is the cluster's private certificate authority (research E019).
//
// `kvoadm init` creates the CA; it never leaves the control plane. Every client certificate carries
// exactly one identity, as a URI SAN, and that identity is all authorization looks at:
//
//	kevaso://host/<name>/role/<role>     a machine's agent (role: control-plane, worker)
//	kevaso://user/<name>/role/<role>     a person or tool (role: cluster-admin until M4's RBAC)
//
// When signing a CSR, only its public key is used: the identity comes from what the caller (a join
// token, the admin socket) allowed, never from fields the requester put in the CSR.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Identity is who a certificate belongs to.
type Identity struct {
	Type string // "host" or "user"
	Name string
	Role string
}

var segment = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// Validate checks the identity can be written as a URI and read back unambiguously.
func (id Identity) Validate() error {
	if id.Type != "host" && id.Type != "user" {
		return fmt.Errorf("identity type %q: want host or user", id.Type)
	}
	if !segment.MatchString(id.Name) || !segment.MatchString(id.Role) {
		return fmt.Errorf("identity %s/%s: name and role must be lowercase letters, digits, '-' or '.'", id.Name, id.Role)
	}
	return nil
}

// URI is the identity's SAN.
func (id Identity) URI() *url.URL {
	return &url.URL{Scheme: "kevaso", Host: id.Type, Path: "/" + id.Name + "/role/" + id.Role}
}

func (id Identity) String() string {
	if id.Role == "" {
		return id.Type + ":" + id.Name
	}
	return id.Type + ":" + id.Name + " (" + id.Role + ")"
}

// ParseIdentity reads an identity URI.
func ParseIdentity(u *url.URL) (Identity, error) {
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if u.Scheme != "kevaso" || len(parts) != 3 || parts[1] != "role" {
		return Identity{}, fmt.Errorf("not a kevaso identity: %s", u)
	}
	id := Identity{Type: u.Host, Name: parts[0], Role: parts[2]}
	return id, id.Validate()
}

// IdentityOf returns the identity of a verified client certificate: exactly one kevaso URI SAN.
func IdentityOf(cert *x509.Certificate) (Identity, error) {
	if len(cert.URIs) != 1 {
		return Identity{}, fmt.Errorf("certificate has %d URI SANs, want exactly 1", len(cert.URIs))
	}
	return ParseIdentity(cert.URIs[0])
}

// CA is the cluster certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	PEM  []byte // the certificate, for clients to pin
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

// NewCA creates a CA valid for ten years.
func NewCA(clusterName string, now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "kevaso " + clusterName + " CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, PEM: pemCert(der)}, nil
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Pool is a cert pool holding only this CA, for clients and for verifying client certificates.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Save writes ca.crt (0644) and ca.key (0600) into dir.
func (ca *CA) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "ca.crt"), ca.PEM, 0o644)
}

// LoadCA reads what Save wrote.
func LoadCA(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("ca files: not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca.key: not a signing key")
	}
	return &CA{Cert: cert, Key: signer, PEM: certPEM}, nil
}

// ServerCert issues the API server's certificate for the given DNS names and IP addresses.
func (ca *CA) ServerCert(names []string, now time.Time, ttl time.Duration) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "kevaso-apiserver"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// SignCSR issues a client certificate for the CSR's public key, with exactly the given identity.
// The CSR's own subject and SANs are ignored: whoever calls SignCSR decides the identity.
func (ca *CA) SignCSR(csrPEM []byte, id Identity, now time.Time, ttl time.Duration) ([]byte, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	b, _ := pem.Decode(csrPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr: not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: id.Type + ":" + id.Name},
		URIs:         []*url.URL{id.URI()},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	return pemCert(der), nil
}

// NewKeyAndCSR is the client side: a fresh key and a CSR for it. The identity in the CSR is only a
// request; SignCSR decides.
func NewKeyAndCSR(id Identity) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: id.Type + ":" + id.Name},
		URIs:    []*url.URL{id.URI()},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
