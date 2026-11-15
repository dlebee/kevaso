package gate

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// K-076: when the secret can't be injected (the host has been cut off from its control plane
// longer than it may inject without it, or the control plane refused), the silo is told why: the
// gate ends TLS as for any injection and answers 503 with the reason, and logs it. Before, the
// connection was closed with nothing said.
func TestAnInjectionThatCantBeMadeIsExplainedToTheSilo(t *testing.T) {
	e := setup(t, "9")
	why := errors.New("the control plane hasn't answered for 1h0m1s: a secret is injected for at most 1h0m0s without it")
	e.dstMu.Lock()
	e.injErr = why
	e.dstMu.Unlock()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", e.gate)
		},
		TLSClientConfig: &tls.Config{RootCAs: e.silo, ServerName: "api.allowed.test"},
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://api.allowed.test/v1/models")
	if err != nil {
		t.Fatalf("the silo got no answer, only: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), why.Error()) {
		t.Fatalf("%d %q, want 503 with the reason", resp.StatusCode, body)
	}
	e.dstMu.Lock()
	log := strings.Join(e.logged, "\n")
	e.dstMu.Unlock()
	if !strings.Contains(log, why.Error()) {
		t.Errorf("not logged:\n%s", log)
	}
}
