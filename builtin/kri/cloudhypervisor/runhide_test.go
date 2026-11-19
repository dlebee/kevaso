package cloudhypervisor

import (
	"strings"
	"testing"
)

func TestTheVMMSeesOnlyItsOwnRuntimeDirectory(t *testing.T) {
	n := NamesFor(id("web"))
	u := Unit(n, 1, 512, "fw", MAC(id("web")))
	run := "/run/" + strings.TrimSuffix(n.Unit, ".service")
	for _, want := range []string{
		"TemporaryFileSystem=/run\n",
		"BindPaths=" + run + "\n",
		`chown -h "$$u" "$$p"`,
		"sh /dev/" + VG + "/" + n.LV + " " + VMMUser,
		`if [ "$$ok" -ne 1 ]; then echo "not chowning $$1: a link to $$t"`,
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	if strings.Contains(u, "ExecStartPre=+/bin/chown "+VMMUser+" ") {
		t.Errorf("chown follows a link:\n%s", u)
	}
}

func TestTheGuestSerialLogIsCapped(t *testing.T) {
	n := NamesFor(id("web"))
	u := Unit(n, 1, 512, "fw", "m")
	if !strings.Contains(u, "--serial file="+n.Dir+"/serial.fifo") {
		t.Fatalf("the VMM does not write the capped fifo:\n%s", u)
	}
	if strings.Contains(u, "--serial file="+n.Dir+"/serial.log ") || strings.Contains(u, "--serial file="+n.Dir+"/serial.log'") {
		t.Fatalf("the VMM writes serial.log directly:\n%s", u)
	}
	if !strings.Contains(u, `-ge 10485760`) || !strings.Contains(u, n.Dir+"/serial.log.1") {
		t.Fatalf("the serial log is not capped at 10MiB with one older file:\n%s", u)
	}
}
