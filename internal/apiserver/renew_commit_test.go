package apiserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
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

// removalOnGet writes a host removal on the at-th Get of that record while armed, then
// returns it. A renew's check has already passed; the write lands on the Get that would
// record the new serial.
type removalOnGet struct {
	store.Store
	mu    sync.Mutex
	n, at int
	armed bool
	name  string
}

func (g *removalOnGet) arm(at int) {
	g.mu.Lock()
	g.n, g.at, g.armed = 0, at, true
	g.mu.Unlock()
}

func (g *removalOnGet) disarm() {
	g.mu.Lock()
	g.armed = false
	g.mu.Unlock()
}

func (g *removalOnGet) Get(ctx context.Context, key store.Key) (store.Object, error) {
	if key.Kind == hostRemovalKind && key.Name == g.name {
		g.mu.Lock()
		insert := false
		if g.armed {
			g.n++
			insert = g.n == g.at
		}
		g.mu.Unlock()
		if insert {
			rec := hostRemovalRecord{RemovedAt: time.Now().UTC().Truncate(time.Second), Pending: true}
			data, err := json.Marshal(rec)
			if err != nil {
				return store.Object{}, err
			}
			if _, err := g.Create(ctx, key, data); err != nil && !errors.Is(err, store.ErrExists) {
				return store.Object{}, err
			}
		}
	}
	return g.Store.Get(ctx, key)
}

// A renew that is in flight while the host is deleted does not finish with a certificate
// auth would accept. The removal is written on the read that would record the serial, after
// the check has already read none. Repeated, so a removal between those reads cannot pass.
func TestRenewDuringHostDeleteIssuesNothing(t *testing.T) {
	ctx := context.Background()
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inner := store.NewMemory(0)
	gate := &removalOnGet{Store: inner, name: "hv1"}
	tokens := &jointoken.Issuer{Store: inner, Clock: clock.Real{}}
	srv, err := NewWithAuth(gate, clock.Real{}, &Auth{CA: ca, Tokens: tokens})
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
	const runs = 200
	for i := 0; i < runs; i++ {
		if _, err := inner.Delete(ctx, hostRemovalKey("hv1"), 0); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		gate.arm(2) // the check read, then the serial record
		r := httptest.NewRequest(http.MethodPost, "/renew", bytes.NewReader(payload))
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
		out := httptest.NewRecorder()
		srv.renewCert(out, r, pki.Identity{Type: "host", Name: "hv1", Role: "worker"})
		gate.disarm()
		rec, _ := srv.hostRemoval(ctx, "hv1")
		if out.Code == http.StatusOK || len(rec.Serials) != 0 {
			t.Fatalf("run %d: renew %d, serials %v (gets %d)", i, out.Code, rec.Serials, gate.n)
		}
	}
}
