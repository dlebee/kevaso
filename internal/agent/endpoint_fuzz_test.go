package agent_test

import (
	"bufio"
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
)

// FuzzEndpointRequest: any HTTP request a silo can send to its host's local endpoint (ADR 0009),
// byte for byte. Whatever it is, what reaches the control plane always names the silo it came
// from (never anything in the request), only for a request with the header, the endpoint's Host
// and no browser headers, on one of the five routes with its method and a well-formed name; and
// the answer never redirects nor speaks CORS.
//
//	go test ./internal/agent -run '^$' -fuzz FuzzEndpointRequest -fuzztime 60s
func FuzzEndpointRequest(f *testing.F) {
	for _, seed := range []string{
		"GET /v1/secrets/db-password HTTP/1.1\r\nHost: 169.254.42.1\r\nKevaso-Local: 1\r\n\r\n",
		"GET /v1/secrets/db-password?for=30m&wait=10s&approval=a-1 HTTP/1.1\r\nHost: 169.254.42.1\r\nKevaso-Local: 1\r\n\r\n",
		"POST /v1/sign/validator-key?slot=7 HTTP/1.1\r\nHost: 169.254.42.1:80\r\nKevaso-Local: 1\r\nContent-Length: 3\r\n\r\nabc",
		"GET /v1/keys/k HTTP/1.1\r\nHost: 169.254.42.1\r\nKevaso-Local: 1\r\n\r\n",
		"POST /v1/ports/rpc/open?for=1h HTTP/1.1\r\nHost: 169.254.42.1\r\nKevaso-Local: 1\r\nContent-Length: 0\r\n\r\n",
		"POST /v1/ports/rpc/close HTTP/1.1\r\nHost: 169.254.42.1\r\nKevaso-Local: 1\r\nContent-Length: 0\r\n\r\n",
		"GET /v1/secrets/../keys/x HTTP/1.1\r\nHost: 169.254.42.1\r\nKevaso-Local: 1\r\n\r\n",
		"GET /v1/secrets/a%2Fb HTTP/1.1\r\nHost: 169.254.42.1\r\nKevaso-Local: 1\r\n\r\n",
		"GET /v1/secrets/x HTTP/1.1\r\nHost: evil.example\r\nKevaso-Local: 1\r\n\r\n",
		"GET /v1/secrets/x HTTP/1.1\r\nHost: 169.254.42.1\r\nKevaso-Local: 1\r\nOrigin: http://evil\r\n\r\n",
		"GET /v1/secrets/x HTTP/1.1\r\nHost: 169.254.42.1\r\nKevaso-Local: 1\r\nsec-fetch-mode: cors\r\n\r\n",
		"OPTIONS /v1/secrets/x HTTP/1.1\r\nHost: 169.254.42.1\r\nKevaso-Local: 1\r\n\r\n",
		"GET /v1/secrets/x?uid=other&namespace=kevaso-system HTTP/1.1\r\nHost: 169.254.42.1\r\nKevaso-Local: 1\r\nKevaso-Silo: other\r\n\r\n",
	} {
		f.Add([]byte(seed))
	}
	cp := &fakeBroker{}
	cps := httptest.NewServer(cp)
	f.Cleanup(cps.Close)
	me := kri.ID{Namespace: "web3", Name: "node", UID: "uid-node"}
	ep := &agent.Endpoint{Client: client.New(cps.URL), HostName: "hv1", Identify: func(*http.Request) (kri.ID, bool) { return me, true }}
	name := regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)
	routes := map[string]string{client.OpGetSecret: "GET /v1/secrets/", client.OpSign: "POST /v1/sign/", client.OpPublicKey: "GET /v1/keys/",
		client.OpPortOpen: "POST /v1/ports/", client.OpPortClose: "POST /v1/ports/"}

	f.Fuzz(func(t *testing.T, raw []byte) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return // net/http never hands the handler what it can't parse
		}
		before := len(cp.calls())
		w := httptest.NewRecorder()
		ep.ServeHTTP(w, req)
		for k := range w.Header() {
			if strings.HasPrefix(k, "Access-Control-") || k == "Location" {
				t.Fatalf("answer header %s", k)
			}
		}
		if w.Code/100 == 3 {
			t.Fatalf("a redirect: %d", w.Code)
		}
		calls := cp.calls()
		if len(calls) == before {
			return
		}
		got := calls[len(calls)-1]
		switch {
		case got.Namespace != me.Namespace || got.Name != me.Name || got.UID != me.UID || got.Host != "hv1":
			t.Fatalf("relayed as %s/%s (%s) from %s", got.Namespace, got.Name, got.UID, got.Host)
		case req.Header.Get("Kevaso-Local") != "1":
			t.Fatal("relayed without Kevaso-Local: 1")
		case len(req.Header.Values("Origin")) > 0:
			t.Fatal("relayed a browser's request (Origin)")
		case req.Host != "169.254.42.1" && req.Host != "169.254.42.1:80":
			t.Fatalf("relayed with Host %q", req.Host)
		case !name.MatchString(got.Request.Name):
			t.Fatalf("relayed name %q", got.Request.Name)
		case got.Request.Approval != "" && !name.MatchString(got.Request.Approval):
			t.Fatalf("relayed approval %q", got.Request.Approval)
		}
		for k := range req.Header {
			if strings.HasPrefix(http.CanonicalHeaderKey(k), "Sec-Fetch-") {
				t.Fatalf("relayed a browser's request (%s)", k)
			}
		}
		route, ok := routes[got.Request.Op]
		if !ok || !strings.HasPrefix(req.Method+" "+req.URL.Path, route) || !strings.Contains(req.URL.Path, "/"+got.Request.Name) {
			t.Fatalf("op %s name %q from %s %s", got.Request.Op, got.Request.Name, req.Method, req.URL.Path)
		}
		if got.Request.Op != client.OpSign && len(got.Request.Payload) > 0 {
			t.Fatal("a payload relayed for an op that takes none")
		}
	})
}
