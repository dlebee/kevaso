package kong

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kic/kictest"
)

var good = map[string]string{"read-timeout": "5m", "strip-path": "true"}

func TestConformance(t *testing.T) { kictest.Conformance(t, Driver{}, good) }

// Kong's shape is an admin-API call: no files, no separate check, no reload command. The call is
// all three (Kong refuses a bad configuration and keeps what it had).
func TestGolden(t *testing.T) {
	p, err := Driver{}.Render(kictest.Sample(good))
	if err != nil {
		t.Fatal(err)
	}
	c := p.Reload.Call
	if c == nil || p.Config.Path != "" || len(p.Files) != 0 || len(p.Check) != 0 || len(p.Reload.Exec) != 0 {
		t.Fatalf("plan %+v", p)
	}
	if c.Port != 8001 || c.Method != "POST" || c.Path != "/config" || c.ContentType != "application/json" {
		t.Fatalf("call %+v", c)
	}
	kictest.Golden(t, "kong.json", c.Body)
	var d declarative
	if err := json.Unmarshal(c.Body, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Services) != 4 || d.Services[1].Routes[0].HTTPSRedirectStatusCode != 308 || d.Services[3].Routes[0].Protocols[0] != "http" ||
		d.Services[0].ReadTimeout != 300000 || !d.Services[0].Routes[0].StripPath {
		t.Fatalf("services %+v", d.Services)
	}
	if len(d.Routes) != 1 || d.Routes[0].Plugins[0].Name != "request-termination" || len(d.Certificates) != 1 || d.Certificates[0].SNIs[0].Name != "api.example.com" {
		t.Fatalf("routes %+v, certificates %d", d.Routes, len(d.Certificates))
	}
	p2, _ := Driver{}.Render(kictest.Sample(map[string]string{}))
	if p2.Hash() == p.Hash() {
		t.Error("annotations didn't change the plan")
	}
	o := kictest.Sample(nil)
	o.Options = map[string]string{"admin-port": "9001"}
	if p3, _ := (Driver{}).Render(o); p3.Reload.Call.Port != 9001 {
		t.Error("admin-port")
	}
}

func TestBlame(t *testing.T) {
	p, _ := Driver{}.Render(kictest.Sample(good))
	out := `{"code":14,"name":"invalid declarative configuration","flattened_errors":[{"entity_name":"shop.plain.3","entity_type":"service","errors":[{"type":"field","field":"url","message":"invalid"}]}]}`
	if got := (Driver{}).Blame(p, out); !slices.Equal(got, []string{"shop/plain"}) {
		t.Fatalf("blamed %v", got)
	}
}

func TestKongAcceptsIt(t *testing.T) {
	bin, err := exec.LookPath("kong")
	if err != nil {
		t.Skip("kong isn't on this machine")
	}
	p, err := Driver{}.Render(kictest.Real(t, good))
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "kong.json")
	if err := os.WriteFile(f, p.Reload.Call.Body, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "config", "parse", f).CombinedOutput(); err != nil || strings.Contains(string(out), "Error") {
		t.Fatalf("kong config parse: %v\n%s", err, out)
	}
}
