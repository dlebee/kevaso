// Package platform is which operating systems kevasod supports: tested end to end, said by
// kevasod itself. The list is one string literal with a marker in front, so it sits in the
// kevasod binary as it is: kvoadm reads it out of the very binary it is about to install
// (FromBinary) instead of keeping a list of its own, and kevasod prints it (kevasod platforms).
package platform

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
)

// Marker starts the list in a binary.
const Marker = "kevaso-platforms/v1:"

// stamp is the list: ID/VERSION_ID (as in /etc/os-release), comma-separated, ending with ";".
// An OS is added here once the whole end-to-end suite passed on it (test/e2e/METAL.md).
const stamp = Marker + "ubuntu/24.04,debian/12;"

// Platform is one operating system release.
type Platform struct{ ID, Version string }

func (p Platform) String() string { return p.ID + " " + p.Version }

// Parse reads a list (what follows Marker, up to ";").
func Parse(s string) ([]Platform, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, Marker), ";")
	var out []Platform
	for _, item := range strings.Split(s, ",") {
		id, v, ok := strings.Cut(strings.TrimSpace(item), "/")
		if !ok || id == "" || v == "" {
			return nil, fmt.Errorf("platform list: %q", item)
		}
		out = append(out, Platform{id, v})
	}
	return out, nil
}

// Supported is this build's list.
func Supported() []Platform {
	p, err := Parse(stamp)
	if err != nil {
		panic(err) // the literal above is wrong
	}
	return p
}

// Stamp is the list as it sits in the binary (kevasod platforms prints it).
func Stamp() string { return stamp }

// FromBinary reads the list out of a kevasod binary. ok is false for a binary that has none (one
// older than the list).
func FromBinary(b []byte) (list []Platform, ok bool, err error) {
	i := bytes.Index(b, []byte(Marker))
	if i < 0 {
		return nil, false, nil
	}
	rest := b[i+len(Marker):]
	j := bytes.IndexByte(rest, ';')
	if j < 0 || j > 4096 {
		return nil, false, fmt.Errorf("platform list in the binary: no end")
	}
	list, err = Parse(string(rest[:j]))
	return list, err == nil, err
}

// Supports reports whether an OS (os-release ID and VERSION_ID) is on the list.
func Supports(list []Platform, id, version string) bool {
	return slices.Contains(list, Platform{strings.ToLower(id), version})
}

// Names is the list for people: "ubuntu 24.04, debian 12".
func Names(list []Platform) string {
	var n []string
	for _, p := range list {
		n = append(n, p.String())
	}
	return strings.Join(n, ", ")
}
