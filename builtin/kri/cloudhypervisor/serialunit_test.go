package cloudhypervisor

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// systemdEffective applies systemd's specifier and variable rules to a rendered
// command line: %% becomes %, $${ becomes ${, a lone %x is an error, and a bare
// ${ or $NAME is an error. $ followed by anything else (a digit) is left as it is.
func systemdEffective(line string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '%':
			if i+1 < len(line) && line[i+1] == '%' {
				b.WriteByte('%')
				i++
				continue
			}
			return "", fmt.Errorf("lone %% at %d in %q", i, line)
		case '$':
			if i+1 < len(line) && line[i+1] == '$' {
				b.WriteByte('$')
				i++
				continue
			}
			if i+1 < len(line) && line[i+1] == '{' {
				return "", fmt.Errorf("bare ${ at %d in %q", i, line)
			}
			if i+1 < len(line) && (unicode.IsLetter(rune(line[i+1])) || line[i+1] == '_') {
				return "", fmt.Errorf("bare $ variable at %d in %q", i, line)
			}
			b.WriteByte('$')
		default:
			b.WriteByte(line[i])
		}
	}
	return b.String(), nil
}

func TestSystemdEffectiveRules(t *testing.T) {
	got, err := systemdEffective("stat -c %%s $${t#/dev/dm-} $$p")
	if err != nil {
		t.Fatal(err)
	}
	if got != "stat -c %s ${t#/dev/dm-} $p" {
		t.Fatalf("effective: %q", got)
	}
	for _, bad := range []string{"stat -c %s", "r=${t#/dev/dm-}", "chown $u"} {
		if _, err := systemdEffective(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestTheRenderedUnitSurvivesSystemdExpansion(t *testing.T) {
	n := NamesFor(id("web"))
	u := Unit(n, 1, 512, "fw", MAC(id("web")))
	var lines []string
	for _, line := range strings.Split(u, "\n") {
		if strings.HasPrefix(line, "ExecStart=") || strings.HasPrefix(line, "ExecStartPre=") {
			lines = append(lines, line)
		}
	}
	if len(lines) < 2 {
		t.Fatalf("unit command lines:\n%s", u)
	}
	var eff []string
	for _, line := range lines {
		got, err := systemdEffective(line)
		if err != nil {
			t.Fatalf("systemd rewrites %q: %v", line, err)
		}
		eff = append(eff, got)
	}
	joined := strings.Join(eff, "\n")
	for _, want := range []string{
		"stat -c %s",
		"${t#/dev/dm-}",
		`chown -h "$u" "$p"`,
		"while true",
		"|| true",
		"exec 3>&-",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("effective command lines lack %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "|| exit 0") {
		t.Fatalf("the logger exits when a write fails:\n%s", joined)
	}
	start := eff[len(eff)-1]
	closeAt := strings.Index(start, "exec 3>&-")
	vmmAt := strings.Index(start, "cloud-hypervisor")
	if closeAt < 0 || vmmAt < 0 || closeAt > vmmAt {
		t.Fatalf("the VMM keeps its fifo descriptor:\n%s", start)
	}
}
