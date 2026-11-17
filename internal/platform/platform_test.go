package platform

import (
	"slices"
	"testing"
)

func TestSupported(t *testing.T) {
	got := Supported()
	if !slices.Contains(got, Platform{"ubuntu", "24.04"}) || !Supports(got, "Ubuntu", "24.04") || Supports(got, "ubuntu", "22.04") {
		t.Fatalf("list %v", got)
	}
	if Names(got) == "" {
		t.Error("no names")
	}
}

func TestFromBinary(t *testing.T) {
	bin := append(append([]byte("\x7fELF junk\x00"), Stamp()...), "\x00more"...)
	list, ok, err := FromBinary(bin)
	if err != nil || !ok || !slices.Equal(list, Supported()) {
		t.Fatalf("%v %v %v", list, ok, err)
	}
	if _, ok, err := FromBinary([]byte("\x7fELF an older kevasod")); ok || err != nil {
		t.Fatalf("an older binary: %v %v", ok, err)
	}
	if _, _, err := FromBinary([]byte(Marker + "ubuntu/24.04")); err == nil {
		t.Error("an unterminated list was accepted")
	}
	// A real kevasod has the bare marker too (the constant), before the stamp: the stamp is found.
	twice := append(append([]byte("\x7fELF "+Marker+"\x00\x01junk;more\x00"), Stamp()...), "\x00"...)
	if list, ok, err := FromBinary(twice); err != nil || !ok || !slices.Equal(list, Supported()) {
		t.Fatalf("the bare marker first: %v %v %v", list, ok, err)
	}
	if _, err := Parse("ubuntu"); err == nil {
		t.Error("a malformed entry was accepted")
	}
}
