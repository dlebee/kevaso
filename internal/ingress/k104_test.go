package ingress_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/sdk/kic"
)

// K-104, ingress items.

// A template change in an upgrade (the running config rendered by an older driver) with the
// record intact: the record is recognised by the digest of the config it was written with, so a
// class with a broken Ingress still takes changes.
func TestK104ATemplateChangeKeepsTheRecord(t *testing.T) {
	for _, r := range rigs(false) {
		if r.name == "kong" {
			continue // its record is checked by Kong's own fingerprint, not a render
		}
		t.Run(r.name, func(t *testing.T) {
			w := served24(t, r)
			// The older driver rendered one more comment line; the record has that config's digest.
			cfg, p := configPath(t, r), recordPath(t, r)
			older := append([]byte("# an older template\n"), r.px.Files[cfg]...)
			r.px.Files[cfg] = older
			var rec map[string]any
			if err := json.Unmarshal(r.px.Files[p], &rec); err != nil {
				t.Fatal(err)
			}
			rec["config"] = digest(older)
			r.px.Files[p], _ = json.Marshal(rec)
			res, _, _ := settle(t, r, w, &ingress.Memory{}, nil, "", 2)
			if res.Held != "" || leftOutNames(res)[0] != "shop/i03" || len(res.LeftOut) != 2 {
				t.Fatalf("held %q, left out %v", res.Held, res.LeftOut)
			}
			for _, h := range []string{"h03.example.com", "h11.example.com", "h05.example.com", "new.example.com"} {
				if !strings.Contains(r.served(), h) {
					t.Errorf("%s isn't served", h)
				}
			}
		})
	}
}

// Kong's record is kept where only Kong's own user may write (not /tmp).
func TestK104KongsRecordIsNotInTmp(t *testing.T) {
	for _, r := range rigs(false) {
		if r.name != "kong" {
			continue
		}
		p := recordPath(t, r)
		if strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "/var/tmp/") {
			t.Errorf("Kong's record is at %s, a folder anyone in the silo may write", p)
		}
		settle(t, r, want(many(2)...), &ingress.Memory{}, nil, "", 1)
		if _, ok := r.px.Files[p]; !ok {
			t.Errorf("no record at %s", p)
		}
	}
}

func tlsRoute(ing, host string) kic.Route {
	r := route(ing, host, 443)
	r.TLS = true
	return r
}

func cert(ing, host, body string) kic.Certificate {
	return kic.Certificate{Name: ing + "-tls", Ingress: ing, Hosts: []string{host},
		Chain: []byte("-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"), Key: []byte("k-" + body)}
}

// servesCert says whether the proxy serves a certificate whose chain holds body.
func servesCert(r *rig, body string) bool {
	if r.name == "kong" {
		return strings.Contains(r.served(), body)
	}
	files, _, _ := r.px.Snapshot()
	for p, b := range files {
		if strings.HasSuffix(p, ".pem") && strings.Contains(string(b), body) && strings.Contains(r.served(), p) {
			return true
		}
	}
	return false
}

// A held Ingress whose certificate is renewed meanwhile serves the renewed one with its last good
// routes (it would expire otherwise); if the proxy refuses the renewed one, the last good version
// as it was stays.
func TestK104AHeldIngressServesItsRenewedCertificate(t *testing.T) {
	for _, blame := range []bool{true, false} {
		for _, r := range rigs(blame) {
			t.Run(r.name, func(t *testing.T) {
				// The proxy refuses the poisoned host, and a certificate that says "badcert".
				check := r.px.Check
				r.px.Check = func(cfg []byte, files map[string][]byte) string {
					for p, b := range files {
						if strings.Contains(string(cfg), p) && strings.Contains(string(b), "badcert") && strings.HasSuffix(p, ".pem") {
							return "refused: bad certificate"
						}
					}
					return check(cfg, files)
				}
				if r.call != nil {
					call := r.call
					r.call = func(ctx context.Context, c kic.Call) (int, string, error) {
						if strings.Contains(string(c.Body), "badcert") {
							r.calls++
							return 400, "bad certificate", nil
						}
						return call(ctx, c)
					}
				}
				m := &ingress.Memory{}
				w := want(tlsRoute("shop/a", "a.example.com"), route("shop/b", "b.example.com", 81))
				w.State.Certificates = []kic.Certificate{cert("shop/a", "a.example.com", "first")}
				_, good, last := settle(t, r, w, m, nil, "", 1)
				if !servesCert(r, "first") {
					t.Fatal("the first certificate isn't served")
				}
				// a is edited into a refusal, and its certificate renewed.
				w2 := want(tlsRoute("shop/a", poison+".example.com"), route("shop/b", "b.example.com", 81))
				w2.State.Certificates = []kic.Certificate{cert("shop/a", poison+".example.com", "second")}
				w2.State.Certificates[0].Hosts = []string{"a.example.com"} // the same names
				res, good2, last2 := settle(t, r, w2, m, good, last, 2)
				if res.Held != "" || res.LeftOut["shop/a"] == "" || !strings.Contains(r.served(), "a.example.com") {
					t.Fatalf("held %q, left out %v", res.Held, res.LeftOut)
				}
				if !servesCert(r, "second") {
					t.Error("the held Ingress serves its frozen certificate, not the renewed one")
				}
				// Renewed again, into one the proxy refuses: the version served stays.
				w3 := w2
				w3.State.Certificates = []kic.Certificate{cert("shop/a", "a.example.com", "badcert")}
				res, _, _ = settle(t, r, w3, m, good2, last2, 2)
				if res.Held != "" || !strings.Contains(r.served(), "a.example.com") || servesCert(r, "badcert") {
					t.Errorf("held %q, left out %v", res.Held, res.LeftOut)
				}
				if !servesCert(r, "second") && !servesCert(r, "first") {
					t.Error("no certificate of a's served any more")
				}
			})
		}
	}
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
