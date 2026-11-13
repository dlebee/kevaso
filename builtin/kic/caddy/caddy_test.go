package caddy

import (
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kic"
	"kevaso.com/core/sdk/kic/kictest"
)

var good = map[string]string{"flush-interval": "-1", "dial-timeout": "2s"}

func TestConformance(t *testing.T) { kictest.Conformance(t, Driver{}, good) }

func TestGolden(t *testing.T) {
	p, err := Driver{}.Render(kictest.Sample(good))
	if err != nil {
		t.Fatal(err)
	}
	kictest.Golden(t, "Caddyfile", p.Config.Data)
	if len(p.Files) != 1 || !strings.HasPrefix(p.Files[0].Path, CertDir+"/") || !p.Files[0].Secret {
		t.Fatalf("files %+v", p.Files)
	}
	if !slices.Contains(p.Check, kic.ConfigToken) || p.Reload.Exec[0] != "caddy" || p.Reload.Exec[1] != "reload" {
		t.Fatalf("check %v, reload %v", p.Check, p.Reload)
	}
	cfg := string(p.Config.Data)
	for _, want := range []string{"auto_https off", "redir https://{host}{uri} 308", "tls " + p.Files[0].Path, "handle /ws* {",
		"respond \"tok-123_abc.thumbprint-XYZ\" 200", "header_up X-Real-IP {remote_host}"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("no %q", want)
		}
	}
	if strings.Contains(cfg, "https://pending.example.com") {
		t.Error("a host without its certificate yet got an https site")
	}
}

func TestBlame(t *testing.T) {
	p, _ := Driver{}.Render(kictest.Sample(good))
	lines := strings.Split(string(p.Config.Data), "\n")
	n := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "reverse_proxy 10.64.0.6:3000") }) + 1
	out := "Error: adapting config using caddyfile: parsing caddyfile tokens for 'reverse_proxy': wrong argument count, at " + ConfigPath + ".next:" + strconv.Itoa(n)
	if got := (Driver{}).Blame(p, out); !slices.Equal(got, []string{"shop/plain"}) {
		t.Fatalf("blamed %v", got)
	}
}

func TestCaddyAcceptsIt(t *testing.T) {
	bin, err := exec.LookPath("caddy")
	if err != nil {
		t.Skip("caddy isn't on this machine")
	}
	p, err := Driver{}.Render(kictest.Real(t, good))
	if err != nil {
		t.Fatal(err)
	}
	cfg := kictest.Materialize(t, p, t.TempDir())
	if out, err := exec.Command(bin, "validate", "--config", cfg, "--adapter", "caddyfile").CombinedOutput(); err != nil {
		t.Fatalf("caddy validate: %v\n%s", err, out)
	}
}
