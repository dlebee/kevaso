package apiserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

// A renew whose body is read only after the host has been removed does not issue a certificate
// and does not record a serial on the removal. The check at the start of the request has already
// passed; the one that counts is the one after the body is read.
func TestRenewHeldOpenAcrossAHostDeleteIssuesNothing(t *testing.T) {
	ctx := context.Background()
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	tokens := &jointoken.Issuer{Store: st, Clock: clock.Real{}}
	srv, err := NewWithAuth(st, clock.Real{}, &Auth{CA: ca, Tokens: tokens})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tokens.Create(ctx, "hv1", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, csr, err := client.NewKeyAndCSR("hv1")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(CertRequest{Token: tok, Host: "hv1", Role: "worker", CSR: string(csr)})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	srv.enroll(w, httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", w.Code, w.Body.Bytes())
	}
	var issued CertResponse
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(issued.Certificate))
	if block == nil {
		t.Fatal("enrolled certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	_, csr2, err := client.NewKeyAndCSR("hv1-renew")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(CertRequest{CSR: string(csr2)})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	var removed error
	r := httptest.NewRequest(http.MethodPost, "/renew", &removeOnRead{
		rest: bytes.NewReader(payload),
		before: func() {
			once.Do(func() {
				_, removed = srv.revokeHost(ctx, "hv1", "", hostRemovalSnap{})
			})
		},
	})
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	out := httptest.NewRecorder()
	srv.renewCert(out, r, pki.Identity{Type: "host", Name: "hv1", Role: "worker"})
	if removed != nil {
		t.Fatal(removed)
	}
	if out.Code != http.StatusUnauthorized {
		t.Fatalf("renew held across the delete: %d %s, want 401", out.Code, out.Body.Bytes())
	}
	rec, ok := srv.hostRemoval(ctx, "hv1")
	if !ok || len(rec.Serials) != 0 {
		t.Fatalf("removal record after the refused renew: ok=%v serials=%v", ok, rec.Serials)
	}
}

// removeOnRead runs before before returning the rest of the body, so a removal recorded there
// sits between the check at the start of the request and the signing.
type removeOnRead struct {
	rest   *bytes.Reader
	before func()
	once   sync.Once
}

func (b *removeOnRead) Read(p []byte) (int, error) {
	b.once.Do(b.before)
	return b.rest.Read(p)
}

// Close is here so a reader used as a body can be closed. The bytes underneath have none.
func (b *removeOnRead) Close() error { return nil }

var _ io.ReadCloser = (*removeOnRead)(nil)
