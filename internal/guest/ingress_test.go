package guest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
)

func TestIngressRouting(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "api "+r.URL.Path+" host="+r.Host+" xff="+r.Header.Get("X-Forwarded-For"))
	}))
	defer api.Close()
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "admin") }))
	defer admin.Close()
	backend := func(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "http://") }
	in := &Ingress{}
	in.cur.Store(CompileIngress(&client.IngressConfig{
		Routes: []client.IngressRoute{
			{Host: "api.example.com", Path: "/", Backend: backend(api), TLS: true},
			{Host: "api.example.com", Path: "/admin", Backend: backend(admin), TLS: true},
			{Host: "plain.lan", Path: "/", Backend: backend(api)},
		},
		Challenges: map[string]string{"tok123": "tok123.thumb"},
	}))
	get := func(tlsSide bool, host, path string) (int, string, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
		req.RemoteAddr = "198.51.100.7:5555"
		in.Handler(tlsSide).ServeHTTP(rec, req)
		return rec.Code, rec.Body.String(), rec.Header().Get("Location")
	}
	if code, body, _ := get(true, "api.example.com", "/v1/x"); code != 200 || !strings.HasPrefix(body, "api /v1/x host=api.example.com") || !strings.Contains(body, "xff=198.51.100.7") {
		t.Errorf("https route: %d %q", code, body)
	}
	if code, body, _ := get(true, "API.example.com:443", "/admin/users"); code != 200 || body != "admin" {
		t.Errorf("longest prefix: %d %q", code, body)
	}
	if code, _, loc := get(false, "api.example.com", "/v1?a=1"); code != http.StatusPermanentRedirect || loc != "https://api.example.com/v1?a=1" {
		t.Errorf("http → https: %d %q", code, loc)
	}
	if code, body, _ := get(false, "anything.example.com", "/.well-known/acme-challenge/tok123"); code != 200 || body != "tok123.thumb" {
		t.Errorf("acme answer: %d %q", code, body)
	}
	if code, _, _ := get(false, "api.example.com", "/.well-known/acme-challenge/unknown"); code != http.StatusNotFound {
		t.Errorf("unknown token: %d", code)
	}
	if _, body, _ := get(true, "api.example.com", "/.well-known/acme-challenge/tok123"); body == "tok123.thumb" {
		t.Error("acme answers are for port 80 only")
	}
	if code, body, _ := get(false, "plain.lan", "/"); code != 200 || !strings.HasPrefix(body, "api /") {
		t.Errorf("plain host over http: %d %q", code, body)
	}
	if code, _, _ := get(true, "nobody.example.com", "/"); code != http.StatusNotFound {
		t.Errorf("unknown host: %d", code)
	}
}
