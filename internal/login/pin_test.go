package login

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string, notBefore, notAfter time.Time) testCA {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testCA{c, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) leaf(t *testing.T) tls.Certificate {
	t.Helper()
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "srv"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &lk.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: lk}
}

func serveCA(t *testing.T, body []byte, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ca.crt" {
			_, _ = w.Write(body)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// K-056: the pin must cover exactly what is trusted.
func TestPinnedCAIsExactlyWhatIsTrusted(t *testing.T) {
	now := time.Now()
	real := newTestCA(t, "real cluster CA", now.Add(-time.Hour), now.Add(time.Hour))
	evil := newTestCA(t, "evil", now.Add(-time.Hour), now.Add(time.Hour))
	other := newTestCA(t, "another", now.Add(-time.Hour), now.Add(time.Hour))
	expired := newTestCA(t, "expired", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	realLeaf, evilLeaf, expiredLeaf := real.leaf(t), evil.leaf(t), expired.leaf(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: realLeaf.Certificate[0]})
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	truncated := real.pem[:len(real.pem)-40]

	cases := []struct {
		name   string
		pin    testCA
		body   []byte
		server tls.Certificate
		ok     bool
	}{
		{"the CA alone", real, real.pem, realLeaf, true},
		{"the CA with surrounding whitespace", real, cat([]byte("\n\r\n "), real.pem, []byte("\n\n")), realLeaf, true},
		{"the same CA twice", real, cat(real.pem, real.pem), realLeaf, true},
		{"a second certificate after (the audited bypass)", real, cat(real.pem, evil.pem), evilLeaf, false},
		{"a second certificate after, server honest", real, cat(real.pem, evil.pem), realLeaf, false},
		{"a second certificate before", real, cat(evil.pem, real.pem), evilLeaf, false},
		{"three certificates, one foreign in the middle", real, cat(real.pem, other.pem, real.pem), realLeaf, false},
		{"a chain: leaf then CA", real, cat(leafPEM, real.pem), realLeaf, false},
		{"a chain: CA then leaf", real, cat(real.pem, leafPEM), realLeaf, false},
		{"leading garbage", real, cat([]byte("hello\n"), real.pem), realLeaf, false},
		{"leading garbage then an evil CA after", real, cat([]byte("x"), real.pem, evil.pem), evilLeaf, false},
		{"trailing garbage", real, cat(real.pem, []byte("trailing\n")), realLeaf, false},
		{"a private key block after", real, cat(real.pem, key), realLeaf, false},
		{"a truncated block after the CA", real, cat(real.pem, truncated), realLeaf, false},
		{"a broken block before the CA", real, cat([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n"), real.pem), realLeaf, false},
		{"a header inside the block", real, []byte(strings.Replace(string(real.pem), "\n", "\nX-Note: y\n\n", 1)), realLeaf, false},
		{"not a certificate", real, []byte("<html>no</html>"), realLeaf, false},
		{"empty", real, nil, realLeaf, false},
		{"the pinned CA is expired", expired, expired.pem, expiredLeaf, false},
		{"the server holds a certificate of another CA", real, real.pem, evilLeaf, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := serveCA(t, c.body, c.server)
			got, err := FetchCA(context.Background(), srv.URL, mustFP(t, c.pin.pem))
			if !c.ok {
				if err == nil {
					t.Fatalf("accepted; returned %d bytes: %q", len(got), got)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			// What comes back is what gets stored and trusted: the pinned certificate, and only it.
			certs, perr := client.ParseCAs(got)
			if perr != nil || len(certs) != 1 || string(got) != string(c.pin.pem) {
				t.Fatalf("returned %q (%v), want exactly the pinned certificate", got, perr)
			}
		})
	}
}

func mustFP(t *testing.T, caPEM []byte) string {
	t.Helper()
	fp, err := client.Fingerprint(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// K-056: a file with junk or an unreadable block never becomes a pool (what AppendCertsFromPEM
// would have skipped silently is refused), so nothing is trusted that was not looked at.
func TestTrustPoolHoldsOnlyWhatParses(t *testing.T) {
	now := time.Now()
	real := newTestCA(t, "real", now.Add(-time.Hour), now.Add(time.Hour))
	evil := newTestCA(t, "evil", now.Add(-time.Hour), now.Add(time.Hour))
	evilLeaf := evil.leaf(t)
	srv := serveCA(t, nil, evilLeaf)
	for name, ca := range map[string][]byte{
		"evil alone":      evil.pem,
		"junk then evil":  cat([]byte("junk\n"), real.pem, []byte("junk"), evil.pem),
		"a skipped block": cat([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), evil.pem),
	} {
		hc, err := HTTPClient(ca)
		if name == "evil alone" {
			// An explicit CA file naming only the evil CA is that person's choice: it is trusted.
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			continue
		}
		if err == nil {
			resp, gerr := hc.Get(srv.URL)
			if gerr == nil {
				_ = resp.Body.Close()
			}
			t.Errorf("%s: a pool was built (and the evil server answered: %v)", name, gerr == nil)
		}
	}
}
