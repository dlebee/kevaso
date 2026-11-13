package kvo

import (
	"io"
	"unicode"
	"unicode/utf8"
)

// terminalSafe passes text on to a terminal with what could drive it taken out: control
// characters but newline and tab (escape sequences, bells, carriage returns), C1 controls and
// bidirectional overrides. Tables and descriptions go through it: they show what silos and hosts
// wrote into their status (an upkeep check's output, a runtime's message), which isn't trusted.
type terminalSafe struct{ w io.Writer }

func safeTerminal(w io.Writer) io.Writer { return terminalSafe{w} }

func (t terminalSafe) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p))
	for i := 0; i < len(p); {
		r, n := utf8.DecodeRune(p[i:])
		if r == '\n' || r == '\t' || (r != utf8.RuneError || n != 1) && !drives(r) {
			out = append(out, p[i:i+n]...)
		}
		i += n
	}
	if _, err := t.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// drives reports whether a terminal acts on r rather than showing it.
func drives(r rune) bool {
	switch {
	case unicode.IsControl(r), r >= 0x80 && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069: // bidi embeddings, overrides, isolates
		return true
	}
	return false
}
