package transfer

import (
	"fmt"
	"strconv"
	"strings"
)

// Entry is one line of `ls -lAn` in a silo, for the file explorer.
type Entry struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // file | dir | link | other
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
	Time   string `json:"time"`
	Target string `json:"target,omitempty"` // a link's
}

// ParseLs reads `ls -lAn` (GNU or busybox): mode, links, uid, gid, size (or "major, minor"), a
// date of three words (or two, ISO), then the name, spaces and all. Lines it can't read are left
// out.
func ParseLs(out string) []Entry {
	var es []Entry
	for line := range strings.SplitSeq(out, "\n") {
		if e, ok := parseLsLine(strings.TrimRight(line, "\r")); ok {
			es = append(es, e)
		}
	}
	return es
}

func parseLsLine(line string) (Entry, bool) {
	rest := line
	next := func() string {
		rest = strings.TrimLeft(rest, " \t")
		i := strings.IndexAny(rest, " \t")
		if i < 0 {
			w := rest
			rest = ""
			return w
		}
		w := rest[:i]
		rest = rest[i:]
		return w
	}
	mode := next()
	if len(mode) < 10 || strings.IndexByte("-dlcbps", mode[0]) < 0 {
		return Entry{}, false // "total N", errors
	}
	e := Entry{Mode: mode, Type: "other"}
	switch mode[0] {
	case '-':
		e.Type = "file"
	case 'd':
		e.Type = "dir"
	case 'l':
		e.Type = "link"
	}
	next() // links
	next() // uid
	next() // gid
	size := next()
	if mode[0] == 'c' || mode[0] == 'b' {
		next() // "major," "minor"
	} else {
		e.Size, _ = strconv.ParseInt(size, 10, 64)
	}
	d := next()
	words := 3
	if len(d) == 10 && d[4] == '-' && d[7] == '-' {
		words = 2 // 2026-11-13 01:50
	}
	t := []string{d}
	for range words - 1 {
		t = append(t, next())
	}
	e.Time = strings.Join(t, " ")
	if len(rest) < 2 || rest[0] != ' ' {
		return Entry{}, false
	}
	e.Name = rest[1:]
	if e.Type == "link" {
		if n, target, ok := strings.Cut(e.Name, " -> "); ok {
			e.Name, e.Target = n, target
		}
	}
	if e.Name == "" || e.Name == "." || e.Name == ".." {
		return Entry{}, false
	}
	return e, true
}

// ToolMissing says whether a command failed because the silo's image doesn't have tool: exit 126
// or 127 (docker, podman, sh), or the message sudo or a shell prints for it.
func ToolMissing(code int, stderr, tool string) bool {
	low := strings.ToLower(stderr)
	return code == 126 || code == 127 || strings.Contains(low, "executable file not found") ||
		strings.Contains(low, tool+": command not found") || strings.Contains(low, tool+": not found")
}

// ParseSize reads a size like 1024, 500MB, 1GiB or 2G (powers of 1024).
func ParseSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		m      int64
	}{{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"TIB", 1 << 40}, {"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30}, {"TB", 1 << 40}, {"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"T", 1 << 40}, {"B", 1}} {
		if v, ok := strings.CutSuffix(t, u.suffix); ok {
			t, mult = strings.TrimSpace(v), u.m
			break
		}
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("size %q: want a number of bytes, like 500MiB or 2GiB", s)
	}
	return n * mult, nil
}
