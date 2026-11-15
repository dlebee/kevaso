package client

import (
	"strings"
	"testing"
)

func TestParseFingerprintIsStrict(t *testing.T) {
	good := "sha256:" + strings.Repeat("ab", 32)
	if got, err := ParseFingerprint(strings.ToUpper(good[:7]) + good[7:]); err == nil {
		t.Errorf("upper-case prefix accepted: %q", got)
	}
	if got, err := ParseFingerprint("sha256:" + strings.Repeat("AB", 32)); err != nil || got != good {
		t.Errorf("upper-case digits: %q, %v", got, err)
	}
	for _, bad := range []string{"", "sha256:", "sha256:ab", good + "00", "sha1:" + strings.Repeat("ab", 32), "sha256:" + strings.Repeat("zz", 32), strings.Repeat("ab", 32)} {
		if got, err := ParseFingerprint(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}
