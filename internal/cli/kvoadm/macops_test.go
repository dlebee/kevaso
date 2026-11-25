package kvoadm

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestRepointMacPlist(t *testing.T) {
	p := MacWorkerPlist(MacWorkerArgs(HostAddOptions{InitOptions: InitOptions{}, Runtimes: []string{"tart"}}, "https://old:6443", "dev"))
	got, changed, err := RepointMacPlist(p, "https://new.example:6443")
	if err != nil || !changed || !strings.Contains(got, "<string>https://new.example:6443</string>") || strings.Contains(got, "old:6443") {
		t.Fatalf("%v %v\n%s", changed, err, got)
	}
	if _, changed, _ := RepointMacPlist(got, "https://new.example:6443"); changed {
		t.Fatal("the same server is no change")
	}
	if _, _, err := RepointMacPlist("<plist></plist>", "x"); err == nil {
		t.Fatal("a plist with no --server")
	}
	args := MacWorkerArgs(HostAddOptions{InitOptions: InitOptions{}, Runtimes: []string{"tart"}}, "https://s", "dev")
	args[2] = "mini"
	if MacPlistName(MacWorkerPlist(args)) != "mini" {
		t.Fatal("the host's name is read back")
	}
}

func TestMacFencePlist(t *testing.T) {
	p := MacFencePlist(MacFenceArgs([]string{"tart"}, "dev"))
	for _, w := range []string{"<string>com.kevaso.fence</string>", "<string>fence-watch</string>", "<string>--fence-after</string>", "<string>--tart-user</string>", "<string>dev</string>",
		"<string>--runtime</string>", "<string>tart</string>", "/var/log/kevaso-fence.log", "<key>KeepAlive</key><true/>"} {
		if !strings.Contains(p, w) {
			t.Errorf("fence plist lacks %s", w)
		}
	}
}

func TestMacScriptsAreValidShell(t *testing.T) {
	for name, s := range map[string]string{"inspect": MacInspectScript("dev"), "remove": MacRemoveScript("dev", false), "remove+silos": MacRemoveScript("dev", true), "upgrade": MacUpgradeRestart} {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(s)
		if o, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s\n%s", name, err, o, s)
		}
	}
	if strings.Contains(MacRemoveScript("dev", false), "tart delete") || strings.Contains(MacRemoveScript("dev", false), "delete") {
		t.Error("silos' VMs are deleted only with --force")
	}
	if !strings.Contains(MacRemoveScript("dev", true), `delete "$v"`) {
		t.Error("--force deletes the silos' VMs")
	}
	if strings.Contains(MacRemoveScript("dev", true), "rm -rf /Users") {
		t.Error("Tart's own folder is never removed")
	}
}

// macHost answers reset's scripts like a Mac with n silo VMs would.
type macHost struct {
	silos          int
	daemon, binary bool
	ran            []string
}

func (m *macHost) Run(_ context.Context, cmd string, _ []byte) ([]byte, error) {
	m.ran = append(m.ran, cmd)
	if strings.Contains(cmd, "bootout") {
		m.silos, m.daemon, m.binary = 0, false, false
		return nil, nil
	}
	yn := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	return []byte("silos=" + string(rune('0'+m.silos)) + "\ndaemon=" + yn(m.daemon) + "\nbinary=" + yn(m.binary) + "\n"), nil
}

func resetOpts(user string) ResetOptions {
	o := ResetOptions{Yes: true}
	o.User, o.Address = user, "mini.local"
	return o
}

func TestMacResetRefusesSilosUnlessForced(t *testing.T) {
	h := &macHost{silos: 2, daemon: true, binary: true}
	var out bytes.Buffer
	err := runMacReset(context.Background(), h, resetOpts("dev"), bufio.NewReader(strings.NewReader("")), &out)
	if !errors.Is(err, ErrMacSilos) {
		t.Fatalf("%v", err)
	}
	for _, c := range h.ran {
		if strings.Contains(c, "bootout") {
			t.Fatal("nothing is removed while silos are there")
		}
	}
	o := resetOpts("dev")
	o.Force = true
	if err := runMacReset(context.Background(), h, o, bufio.NewReader(strings.NewReader("")), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Kevaso is off this Mac") {
		t.Fatal(out.String())
	}
}

func TestMacResetNeedsAUserAndAYes(t *testing.T) {
	h := &macHost{daemon: true, binary: true}
	if err := runMacReset(context.Background(), h, resetOpts("root"), bufio.NewReader(strings.NewReader("")), &bytes.Buffer{}); err == nil {
		t.Fatal("root accepted")
	}
	o := resetOpts("dev")
	o.Yes = false
	if err := runMacReset(context.Background(), h, o, bufio.NewReader(strings.NewReader("n\n")), &bytes.Buffer{}); err == nil || !h.daemon {
		t.Fatalf("a no still removed things: %v", err)
	}
	o.DryRun = true
	if err := runMacReset(context.Background(), h, o, bufio.NewReader(strings.NewReader("")), &bytes.Buffer{}); !errors.Is(err, ErrDryRun) {
		t.Fatalf("%v", err)
	}
}
