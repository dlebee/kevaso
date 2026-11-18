package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rotatingCert is the certificate a client presents. GetClientCertificate reads it on each
// handshake, so a renewal replaces it for the next connection without building a new client.
type rotatingCert struct {
	mu   sync.Mutex
	cert *tls.Certificate
}

func (r *rotatingCert) current() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert == nil {
		return nil, errors.New("no client certificate")
	}
	return r.cert, nil
}

func (r *rotatingCert) set(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cert = &pair
	r.mu.Unlock()
	return nil
}

// RenewDue reports whether a certificate should be renewed: past two thirds of its lifetime, or
// inside the last ten days, whichever is earlier.
func RenewDue(notBefore, notAfter, now time.Time) bool {
	life := notAfter.Sub(notBefore)
	if life <= 0 {
		return false
	}
	at := notBefore.Add(life * 2 / 3)
	if ten := notAfter.Add(-10 * 24 * time.Hour); ten.Before(at) {
		at = ten
	}
	return !now.Before(at)
}

// NewTLS returns a client that pins the cluster CA and presents a client certificate (both PEM).
// With empty certPEM/keyPEM it connects without one (enough for Enroll).
func NewTLS(baseURL string, caPEM, certPEM, keyPEM []byte) (*Client, error) {
	pool, err := CertPool(caPEM)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	c := New(baseURL)
	if len(certPEM) > 0 {
		rot := &rotatingCert{}
		if err := rot.set(certPEM, keyPEM); err != nil {
			return nil, err
		}
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return rot.current()
		}
		c.certs = rot
	}
	c.HTTP = &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true,
		DialContext: (&net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second,
		// A connection whose peer went silent (no RST: powered off, cut off) is found by its
		// pings and closed, so neither new requests nor a watch wait on it (K-008).
		HTTP2: &http.HTTP2Config{SendPingTimeout: PingAfter, PingTimeout: PingTimeout}}}
	return c, nil
}

// DialTimeout bounds connecting to a control plane. Without one, a powered-off machine (no RST,
// just silence) holds each request for the OS's connect timeout, a minute or two, before the
// client fails over to the next system node.
const DialTimeout = 5 * time.Second

// NewUnix returns a client for the admin socket at path (root on a control-plane host).
func NewUnix(path string) *Client {
	c := New("http://admin")
	c.HTTP = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
	}}
	return c
}

// Credentials are a client certificate, its key and the CA that signed it (all PEM).
type Credentials struct {
	Certificate []byte
	Key         []byte
	CA          []byte
}

type certRequest struct {
	Token string `json:"token,omitempty"`
	Host  string `json:"host,omitempty"`
	Role  string `json:"role,omitempty"`
	Name  string `json:"name,omitempty"`
	CSR   string `json:"csr"`
}

type certResponse struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
}

func newKeyAndCSR(cn string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
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

func (c *Client) requestCert(ctx context.Context, path string, req certRequest) (Credentials, error) {
	keyPEM, csrPEM, err := newKeyAndCSR(req.Host + req.Name)
	if err != nil {
		return Credentials{}, err
	}
	req.CSR = string(csrPEM)
	var resp certResponse
	if err := c.do(ctx, http.MethodPost, path, req, &resp); err != nil {
		return Credentials{}, err
	}
	return Credentials{Certificate: []byte(resp.Certificate), Key: keyPEM, CA: []byte(resp.CA)}, nil
}

// Renew asks for a new certificate for whoever this client already is. The server signs that
// identity; the CSR's names are ignored.
func (c *Client) Renew(ctx context.Context) (Credentials, error) {
	return c.requestCert(ctx, "/renew", certRequest{})
}

// RotateCertificate presents certPEM on the next handshake. The client keeps using the connection
// it has until that connection is idle.
func (c *Client) RotateCertificate(certPEM, keyPEM []byte) error {
	if c == nil || c.certs == nil {
		return errors.New("this client has no certificate to rotate")
	}
	if err := c.certs.set(certPEM, keyPEM); err != nil {
		return err
	}
	if c.HTTP != nil {
		c.HTTP.CloseIdleConnections()
	}
	return nil
}

// Enroll joins a host: the key never leaves this machine; the server signs a CSR for exactly the
// host and role the join token allows. Use a client from NewTLS with the pinned CA and no cert.
func (c *Client) Enroll(ctx context.Context, token, host, role string) (Credentials, error) {
	return c.requestCert(ctx, "/enroll", certRequest{Token: token, Host: host, Role: role})
}

// SignUserCSR mints a cluster-admin certificate for name from a CSR made elsewhere (so the key
// never leaves the machine that made it). Only works over the admin socket.
func (c *Client) SignUserCSR(ctx context.Context, name string, csrPEM []byte) (certPEM, caPEM []byte, err error) {
	var resp certResponse
	if err := c.do(ctx, http.MethodPost, "/admin/certs", certRequest{Name: name, CSR: string(csrPEM)}, &resp); err != nil {
		return nil, nil, err
	}
	return []byte(resp.Certificate), []byte(resp.CA), nil
}

// NewKeyAndCSR makes a fresh key and a CSR for it (PEM).
func NewKeyAndCSR(cn string) (keyPEM, csrPEM []byte, err error) { return newKeyAndCSR(cn) }

// IssueUserCert mints a cluster-admin certificate for name. Only works over the admin socket.
func (c *Client) IssueUserCert(ctx context.Context, name string) (Credentials, error) {
	return c.requestCert(ctx, "/admin/certs", certRequest{Name: name})
}

// ParseCAs reads a file of CA certificates strictly: only CERTIFICATE blocks (no headers) that
// parse, and nothing else, not even before the first or after the last block. Whatever
// pem.Decode or AppendCertsFromPEM would skip silently is an error here, so what was checked is
// exactly what is trusted.
func ParseCAs(caPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := caPEM
	for {
		p := bytes.TrimLeft(rest, " \t\r\n")
		if len(p) == 0 {
			break
		}
		if !bytes.HasPrefix(p, []byte("-----BEGIN ")) {
			return nil, errors.New("CA: data outside a PEM block")
		}
		blk, r := pem.Decode(p)
		if blk == nil {
			return nil, errors.New("CA: malformed PEM block")
		}
		used := p[:len(p)-len(r)]
		if bytes.Count(used, []byte("-----BEGIN ")) != 1 || bytes.Count(used, []byte("-----END ")) != 1 {
			return nil, errors.New("CA: malformed PEM block")
		}
		if blk.Type != "CERTIFICATE" || len(blk.Headers) > 0 {
			return nil, fmt.Errorf("CA: a %q block, only plain certificates are accepted", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("CA: unreadable certificate: %w", err)
		}
		certs = append(certs, c)
		rest = r
	}
	if len(certs) == 0 {
		return nil, errors.New("CA: no certificate in PEM")
	}
	return certs, nil
}

// CertPool is the trust pool of exactly the certificates ParseCAs found.
func CertPool(caPEM []byte) (*x509.CertPool, error) {
	certs, err := ParseCAs(caPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ParseFingerprint checks a pin is "sha256:" and 64 hex digits and returns it in lower case.
func ParseFingerprint(fp string) (string, error) {
	h, ok := strings.CutPrefix(strings.TrimSpace(fp), "sha256:")
	if !ok || len(h) != 64 {
		return "", errors.New("a CA fingerprint is sha256: followed by 64 hex digits")
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", errors.New("a CA fingerprint is sha256: followed by 64 hex digits")
	}
	return "sha256:" + strings.ToLower(h), nil
}

// PinCA accepts caPEM only if every certificate in it has the pinned fingerprint (a file with a
// second, different certificate is refused whole, wherever it sits). It returns the one pinned
// certificate, re-encoded, which is the only thing to store and trust.
func PinCA(caPEM []byte, fingerprint string) ([]byte, error) {
	want, err := ParseFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	certs, err := ParseCAs(caPEM)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if got := fingerprintOf(c.Raw); got != want {
			return nil, fmt.Errorf("the cluster's CA file holds a certificate %s, not the %s you were given: not trusting it", got, want)
		}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw}), nil
}

// Fingerprint is how a CA is named for pinning: "sha256:" and the hex SHA-256 of its
// certificate's DER. The PEM must hold exactly one certificate (copies of it are fine).
func Fingerprint(caPEM []byte) (string, error) {
	certs, err := ParseCAs(caPEM)
	if err != nil {
		return "", err
	}
	fp := fingerprintOf(certs[0].Raw)
	for _, c := range certs[1:] {
		if fingerprintOf(c.Raw) != fp {
			return "", errors.New("CA: more than one certificate; a pin names exactly one")
		}
	}
	return fp, nil
}
