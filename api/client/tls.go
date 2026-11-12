package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
)

// NewTLS returns a client that pins the cluster CA and presents a client certificate (both PEM).
// With empty certPEM/keyPEM it connects without one (enough for Enroll).
func NewTLS(baseURL string, caPEM, certPEM, keyPEM []byte) (*Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA: no certificate in PEM")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	if len(certPEM) > 0 {
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	c := New(baseURL)
	c.HTTP = &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}}
	return c, nil
}

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
