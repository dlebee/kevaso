package client

import "testing"

func TestWarningText(t *testing.T) {
	for h, want := range map[string]string{
		`299 - "plain"`:                    "plain",
		`299 - "a \"quoted\" \\ word"`:     `a "quoted" \ word`,
		`199 - "not ours"`:                 "",
		`299 - "unterminated`:              "",
		`299 - "secret x: docker inspect"`: "secret x: docker inspect",
	} {
		got, ok := WarningText(h)
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v, want %q", h, got, ok, want)
		}
	}
}
