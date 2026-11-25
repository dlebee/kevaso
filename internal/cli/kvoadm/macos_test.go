package kvoadm

import (
	"encoding/binary"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/internal/platform"
)

func macFacts() map[string]string {
	return map[string]string{"os": "macOS 26.6.2", "os_id": "macos", "os_version": "26", "arch": "arm64", "uid": "501", "user": "dev",
		"launchd": "yes", "openssl3": "yes", "tart": "2.41.1", "softnet": "yes", "cpus": "12", "memory_mib": "36864", "disk_free_gib": "400",
		"password_login": "no", "kevasod": "absent", "port_6443": "free"}
}

func levels(rs []CheckResult) map[string]string {
	m := map[string]string{}
	for _, r := range rs {
		m[r.What] = r.Level
	}
	return m
}

var sup = Supported{List: platform.Supported(), From: "kevasod"}

func TestMacCheckFit(t *testing.T) {
	for _, r := range AssessWith(macFacts(), sup) {
		if r.Level == "fail" {
			t.Fatalf("a good Mac fails: %+v", r)
		}
	}
	if levels(AssessWith(macFacts(), sup))["macOS worker"] != "warn" {
		t.Fatal("a Mac worker is new and says so")
	}
}

func TestMacCheckFindsWhatIsMissing(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(map[string]string)
		which string
	}{
		{"intel", func(f map[string]string) { f["arch"] = "x86_64" }, "CPU"},
		{"old macOS", func(f map[string]string) { f["os_version"] = "12" }, "macOS version"},
		{"no tart", func(f map[string]string) { f["tart"] = "no" }, "tart"},
		{"libressl", func(f map[string]string) { delete(f, "openssl3") }, "openssl"},
		{"port taken", func(f map[string]string) { f["port_6443"] = "taken" }, "port 6443"},
	}
	for _, c := range cases {
		f := macFacts()
		c.edit(f)
		if got := levels(AssessWith(f, sup))[c.which]; got != "fail" {
			t.Errorf("%s: %s is %q, want fail", c.name, c.which, got)
		}
	}
	f := macFacts()
	f["softnet"] = "no"
	f["uid"] = "0"
	l := levels(AssessWith(f, sup))
	if l["softnet"] != "warn" || l["account"] != "fail" {
		t.Errorf("no softnet is a warning, logging in as root is not accepted: %v", l)
	}
}

func TestLinuxCheckUnchangedByMac(t *testing.T) {
	// A Linux machine still goes the Linux way (systemd is checked, tart never is).
	rs := AssessWith(map[string]string{"os": "Ubuntu 24.04", "os_id": "ubuntu", "os_version": "24.04", "arch": "x86_64", "uid": "0", "systemd": "yes", "openssl": "yes", "apt": "yes", "kvm": "yes",
		"cpus": "4", "memory_mib": "8000", "password_login": "no"}, sup)
	l := levels(rs)
	if _, ok := l["tart"]; ok {
		t.Fatal("tart on Linux")
	}
	if l["systemd"] != "ok" {
		t.Fatalf("%v", l)
	}
}

func TestMacPlist(t *testing.T) {
	args := MacWorkerArgs(HostAddOptions{InitOptions: InitOptions{}, Runtimes: []string{"tart"}}, "https://cp.example:6443", "dev")
	args[2] = "mini & co" // --name
	p := MacWorkerPlist(args)
	d := xml.NewDecoder(strings.NewReader(p))
	d.Strict = true
	d.Entity = xml.HTMLEntity
	for {
		if _, err := d.Token(); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("not well-formed XML: %v\n%s", err, p)
		}
	}
	for _, want := range []string{"<string>com.kevaso.kevasod</string>", "<string>/usr/local/bin/kevasod</string>", "<string>worker</string>",
		"<string>mini &amp; co</string>", "<string>--runtime</string>", "<string>tart</string>", "<string>--tart-user</string>", "<string>dev</string>",
		"/opt/homebrew/bin", "<key>KeepAlive</key><true/>"} {
		if !strings.Contains(p, want) {
			t.Errorf("plist lacks %s\n%s", want, p)
		}
	}
}

func TestMacRefusesLinuxOnlyOptions(t *testing.T) {
	o := HostAddOptions{Runtimes: []string{"tart"}}
	if got := macRefusals(o); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	o.Runtimes = []string{"cloud-hypervisor"}
	o.LoopStorage = "64G"
	o.Install = "control-plane"
	got := strings.Join(macRefusals(o), ";")
	for _, w := range []string{"--runtime cloud-hypervisor", "--loop-storage", "--install control-plane"} {
		if !strings.Contains(got, w) {
			t.Errorf("%q not named in %q", w, got)
		}
	}
}

func TestBinaryTarget(t *testing.T) {
	dir := t.TempDir()
	macho := func(cpu uint32) string {
		b := make([]byte, 32)
		binary.LittleEndian.PutUint32(b[0:], 0xfeedfacf) // MH_MAGIC_64
		binary.LittleEndian.PutUint32(b[4:], cpu)
		binary.LittleEndian.PutUint32(b[12:], 2) // MH_EXECUTE
		p := filepath.Join(dir, "kevasod-darwin")
		if err := os.WriteFile(p, b, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if goos, arch, err := BinaryTarget(macho(0x0100000c)); err != nil || goos != "darwin" || arch != "arm64" {
		t.Fatalf("%s %s %v", goos, arch, err)
	}
	if goos, arch, err := BinaryTarget(macho(0x01000007)); err != nil || goos != "darwin" || arch != "x86_64" {
		t.Fatalf("%s %s %v", goos, arch, err)
	}
	junk := filepath.Join(dir, "junk")
	_ = os.WriteFile(junk, []byte("not a binary"), 0o755)
	if _, _, err := BinaryTarget(junk); err == nil {
		t.Fatal("junk accepted")
	}
}
