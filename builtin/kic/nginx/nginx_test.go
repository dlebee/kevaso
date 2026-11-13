package nginx

import (
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kic"
	"kevaso.com/core/sdk/kic/kictest"
)

var good = map[string]string{"proxy-body-size": "10m", "proxy-read-timeout": "1h", "buffering": "false"}

func TestConformance(t *testing.T) { kictest.Conformance(t, Driver{}, good) }

// The whole nginx.conf for the sample: the redirect, SNI per host, path prefixes, WebSocket
// upgrade, the challenge path, timeouts and the client address headers.
func TestGolden(t *testing.T) {
	p, err := Driver{}.Render(kictest.Sample(good))
	if err != nil {
		t.Fatal(err)
	}
	kictest.Golden(t, "nginx.conf", p.Config.Data)
	if len(p.Files) != 1 || !strings.HasPrefix(p.Files[0].Path, CertDir+"/") || p.Files[0].Mode != 0o600 || !p.Files[0].Secret ||
		string(p.Files[0].Data) != kictest.Chain+"\n"+kictest.Key {
		t.Fatalf("files %+v", p.Files)
	}
	if !slices.Equal(p.Check, []string{"nginx", "-t", "-q", "-c", kic.ConfigToken}) || !slices.Equal(p.Reload.Exec, []string{"nginx", "-s", "reload"}) {
		t.Fatalf("check %v, reload %v", p.Check, p.Reload)
	}
	cfg := string(p.Config.Data)
	for _, want := range []string{
		"return 308 https://$host$request_uri;",    // HTTP → HTTPS
		"ssl_certificate " + p.Files[0].Path + ";", // SNI: the host's own certificate
		"location /ws {", // a path prefix
		"proxy_set_header Upgrade $http_upgrade;", // WebSocket
		"location = /.well-known/acme-challenge/tok-123_abc {",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"ssl_reject_handshake on;", // no certificate for an unknown name
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("no %q", want)
		}
	}
	if strings.Contains(cfg, "server_name pending.example.com;\n    ssl") || strings.Count(cfg, "listen 443 ssl;") != 1 {
		t.Error("a host without its certificate yet got a 443 server")
	}
}

func TestOptions(t *testing.T) {
	s := kictest.Sample(nil)
	s.Options = map[string]string{"worker-connections": "4096", "http2": "true", "user": "www-data"}
	if err := kic.Validate(Driver{}, s); err != nil {
		t.Fatal(err)
	}
	p, _ := Driver{}.Render(s)
	for _, want := range []string{"worker_connections 4096;", "http2 on;", "user www-data;"} {
		if !strings.Contains(string(p.Config.Data), want) {
			t.Errorf("no %q", want)
		}
	}
	s.Options = map[string]string{"http2": "yes"}
	if err := kic.Validate(Driver{}, s); err == nil {
		t.Error("http2: yes accepted")
	}
}

func TestSSLRedirectOff(t *testing.T) {
	p, _ := Driver{}.Render(kictest.Sample(map[string]string{"ssl-redirect": "false"}))
	plain := strings.Split(string(p.Config.Data), "server_name api.example.com;")[1] // the port 80 server
	plain, _, _ = strings.Cut(plain, "server {")
	if strings.Contains(plain, "return 308") || !strings.Contains(plain, "proxy_pass http://10.64.0.4:8080;") {
		t.Fatalf("ssl-redirect false still redirects:\n%s", plain)
	}
}

// nginx -t names the line it stopped at: the Ingress whose section holds it is blamed.
func TestBlame(t *testing.T) {
	p, _ := Driver{}.Render(kictest.Sample(good))
	lines := strings.Split(string(p.Config.Data), "\n")
	n := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "proxy_pass http://10.64.0.6:3000;") }) + 1
	out := "nginx: [emerg] host not found in upstream \"x\" in " + ConfigPath + ":" + strconv.Itoa(n) + "\nnginx: configuration file " + ConfigPath + " test failed"
	if got := (Driver{}).Blame(p, out); !slices.Equal(got, []string{"shop/plain"}) {
		t.Fatalf("blamed %v for line %d", got, n)
	}
	if got := (Driver{}).Blame(p, "nginx: [emerg] unknown directive in "+ConfigPath+":3"); got != nil {
		t.Fatalf("blamed %v for the global part", got)
	}
}

// With nginx on this machine, its own check runs on what was rendered (paths moved to a temporary
// folder). Skipped without it: nothing is installed for this.
func TestNginxAcceptsIt(t *testing.T) {
	bin, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("nginx isn't on this machine")
	}
	s := kictest.Real(t, good)
	s.Options = map[string]string{"pid": "/tmp/kvo-nginx-test.pid"}
	p, err := Driver{}.Render(s)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := kictest.Materialize(t, p, dir, "/var/log/nginx", "/tmp/kvo-nginx-test.pid")
	// nginx -t opens its listening sockets, and a test doesn't run as root: move 80 and 443 up.
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	moved := strings.NewReplacer("listen 80", "listen 18080", "listen 443", "listen 18443").Replace(string(b))
	if moved == string(b) {
		t.Fatal("no listen 80 / 443 found to move: the test would need root")
	}
	// …and its temporary folders default to places only root can make.
	var temps strings.Builder
	for _, d := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		temps.WriteString("\n    " + d + "_temp_path " + dir + "/tmp_" + d + ";")
	}
	withTemps := strings.Replace(moved, "http {", "http {"+temps.String(), 1)
	if withTemps == moved {
		t.Fatal("no http block found")
	}
	moved = withTemps
	if err := os.WriteFile(cfg, []byte(moved), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "-t", "-q", "-p", dir, "-c", cfg, "-e", dir+"/error.log").CombinedOutput(); err != nil {
		t.Fatalf("nginx -t: %v\n%s", err, out)
	}
}
