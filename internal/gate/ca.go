package gate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA is a host's egress CA: its silos trust it, and the gate mints a certificate from it for each
// host a secret is injected for. Each host has its own, made on the host, never leaving it: a
// compromised host can only stand in the middle of its own silos' traffic, which it carries anyway.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	PEM  []byte

	mu     sync.Mutex
	leaves map[string]tls.Certificate
}

// LoadOrCreateCA reads dir/ca.crt and dir/ca.key, or makes them (key 0600).
func LoadOrCreateCA(dir, hostName string) (*CA, error) {
	certPEM, err1 := os.ReadFile(filepath.Join(dir, "ca.crt"))
	keyPEM, err2 := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err1 == nil && err2 == nil {
		return parseCA(certPEM, keyPEM)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "Kevaso egress CA (" + hostName + ")"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0o644); err != nil {
		return nil, err
	}
	return parseCA(certPEM, keyPEM)
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("egress CA: bad PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("egress CA: not an ECDSA key")
	}
	return &CA{cert: cert, key: key, PEM: certPEM, leaves: map[string]tls.Certificate{}}, nil
}

// Leaf is a certificate for host, minted once and kept for a day.
func (ca *CA) Leaf(host string) (tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.leaves[host]; ok && time.Now().Before(c.Leaf.NotAfter.Add(-time.Hour)) {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	c := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	ca.leaves[host] = c
	return c, nil
}
