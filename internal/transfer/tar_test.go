package transfer

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type entry struct {
	name, body, link string
	typ              byte
}

func mkTar(t *testing.T, es ...entry) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, Linkname: e.link}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if e.typ == tar.TypeDir {
			h.Mode = 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(e.body))
	}
	_ = tw.Close()
	return &b
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPackThenUnpack(t *testing.T) {
	src := t.TempDir()
	_ = os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha"), 0o640)
	_ = os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("beta"), 0o755)
	_ = os.Symlink("a.txt", filepath.Join(src, "link"))
	var b bytes.Buffer
	res, err := Pack(&b, src, "proj", DefaultLimit)
	if err != nil || res.Files != 2 || res.Dirs != 2 || res.Links != 1 || res.Bytes != 9 {
		t.Fatalf("pack: %+v %v", res, err)
	}
	// What a silo's tar would send back for that folder: the same entries under ./proj.
	var again bytes.Buffer
	tr, tw := tar.NewReader(&b), tar.NewWriter(&again)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		h.Name = "./" + h.Name
		_ = tw.WriteHeader(h)
		body := make([]byte, h.Size)
		_, _ = tr.Read(body)
		_, _ = tw.Write(body)
	}
	_ = tw.Close()
	dst := t.TempDir()
	res, err = Unpack(&again, dst, "proj", "copy", DefaultLimit)
	if err != nil || res.Files != 2 || res.Links != 1 {
		t.Fatalf("unpack: %+v %v", res, err)
	}
	if read(t, filepath.Join(dst, "copy", "a.txt")) != "alpha" || read(t, filepath.Join(dst, "copy", "sub", "b.txt")) != "beta" {
		t.Fatal("contents")
	}
	if l, _ := os.Readlink(filepath.Join(dst, "copy", "link")); l != "a.txt" {
		t.Fatalf("link %q", l)
	}
	if fi, _ := os.Stat(filepath.Join(dst, "copy", "sub", "b.txt")); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestPackRefusesOverTheLimit(t *testing.T) {
	src := filepath.Join(t.TempDir(), "big")
	_ = os.WriteFile(src, bytes.Repeat([]byte("x"), 100), 0o644)
	if _, err := Pack(&bytes.Buffer{}, src, "big", 99); !errors.Is(err, ErrTooBig) {
		t.Fatalf("want ErrTooBig, got %v", err)
	}
	if _, err := Pack(&bytes.Buffer{}, src, "../x", 1000); err == nil {
		t.Fatal("packed under a name with a slash")
	}
}

// Nothing in a tar from a silo writes outside the destination.
func TestUnpackStaysInsideTheDestination(t *testing.T) {
	outside := t.TempDir()
	cases := map[string]*bytes.Buffer{
		"dot-dot":           mkTar(t, entry{name: "./f/../../escape", typ: tar.TypeReg, body: "x"}),
		"absolute":          mkTar(t, entry{name: "/etc/escape", typ: tar.TypeReg, body: "x"}),
		"not what we asked": mkTar(t, entry{name: "./other/escape", typ: tar.TypeReg, body: "x"}),
		"backslash":         mkTar(t, entry{name: `./f\..\..\escape`, typ: tar.TypeReg, body: "x"}),
	}
	for name, tb := range cases {
		dst := t.TempDir()
		if _, err := Unpack(tb, dst, "f", "f", DefaultLimit); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
	// A link pointing outside, then a file written "through" it: the link is skipped, and the
	// file lands inside, never in the folder the link named.
	dst := t.TempDir()
	tb := mkTar(t,
		entry{name: "./f/", typ: tar.TypeDir},
		entry{name: "./f/out", typ: tar.TypeSymlink, link: outside},
		entry{name: "./f/up", typ: tar.TypeSymlink, link: "../.."},
		entry{name: "./f/out/pwned", typ: tar.TypeReg, body: "x"},
		entry{name: "./f/ok", typ: tar.TypeSymlink, link: "out/pwned"},
	)
	res, err := Unpack(tb, dst, "f", "f", DefaultLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 2 || res.Links != 1 {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned")); err == nil {
		t.Fatal("a file was written outside the destination")
	}
	if read(t, filepath.Join(dst, "f", "out", "pwned")) != "x" {
		t.Fatal("the file should land inside")
	}
	// A link already in the destination (planted, or from an earlier copy) isn't written through.
	dst = t.TempDir()
	_ = os.MkdirAll(filepath.Join(dst, "f"), 0o755)
	_ = os.Symlink(filepath.Join(outside, "victim"), filepath.Join(dst, "f", "file"))
	if _, err := Unpack(mkTar(t, entry{name: "./f/file", typ: tar.TypeReg, body: "x"}), dst, "f", "f", DefaultLimit); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "victim")); err == nil {
		t.Fatal("wrote through a link in the destination")
	}
	_ = os.Symlink(outside, filepath.Join(dst, "f", "dirlink"))
	if _, err := Unpack(mkTar(t, entry{name: "./f/dirlink/x", typ: tar.TypeReg, body: "x"}), dst, "f", "f", DefaultLimit); err == nil {
		t.Fatal("wrote through a folder link pointing outside")
	}
	if _, err := os.Stat(filepath.Join(outside, "x")); err == nil {
		t.Fatal("wrote through a folder link pointing outside")
	}
}

func TestUnpackLimitsAndOddEntries(t *testing.T) {
	dst := t.TempDir()
	tb := mkTar(t, entry{name: "./f", typ: tar.TypeReg, body: "0123456789"})
	if _, err := Unpack(tb, dst, "f", "f", 9); !errors.Is(err, ErrTooBig) {
		t.Fatalf("want ErrTooBig, got %v", err)
	}
	tb = mkTar(t, entry{name: "./", typ: tar.TypeDir}, entry{name: "./etc/", typ: tar.TypeDir},
		entry{name: "./etc/hosts", typ: tar.TypeReg, body: "h"}, entry{name: "./dev/null", typ: tar.TypeChar},
		entry{name: "./etc/hard", typ: tar.TypeLink, link: "/etc/shadow"})
	res, err := Unpack(tb, dst, "", "root", DefaultLimit) // the silo's "/"
	if err != nil || len(res.Skipped) != 2 || read(t, filepath.Join(dst, "root", "etc", "hosts")) != "h" {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := Unpack(mkTar(t), dst, "f", "../x", DefaultLimit); err == nil {
		t.Fatal("unpacked under a name with a slash")
	}
}

func TestFirstFileAndOneFile(t *testing.T) {
	var b bytes.Buffer
	if err := OneFile(&b, "notes.txt", 5, strings.NewReader("hello, and more")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	h, err := FirstFile(&b, &out, 100)
	if err != nil || h.Name != "notes.txt" || out.String() != "hello" {
		t.Fatalf("%v %v %q", h, err, out.String())
	}
	if err := OneFile(&b, "../x", 1, strings.NewReader("x")); err == nil {
		t.Fatal("OneFile took a name with a slash")
	}
	if _, err := FirstFile(mkTar(t, entry{name: "./d/", typ: tar.TypeDir}), &out, 100); err == nil {
		t.Fatal("a folder read as a file")
	}
}

func TestParseLs(t *testing.T) {
	gnu := `total 12
drwxr-xr-x 2 0 0 4096 Nov 13 01:50 bin
-rw-r--r-- 1 1000 1000 123 Jan  2  2025 my notes.txt
lrwxrwxrwx 1 0 0 7 Nov 13 01:50 lib -> usr/lib
crw-rw-rw- 1 0 0 1, 3 Nov 13 01:50 null
-rw-r--r-- 1 0 0 5 2026-11-13 01:50 iso
ls: cannot access 'x': No such file or directory`
	es := ParseLs(gnu)
	want := []Entry{
		{Name: "bin", Type: "dir", Size: 4096, Mode: "drwxr-xr-x", Time: "Nov 13 01:50"},
		{Name: "my notes.txt", Type: "file", Size: 123, Mode: "-rw-r--r--", Time: "Jan 2 2025"},
		{Name: "lib", Type: "link", Size: 7, Mode: "lrwxrwxrwx", Time: "Nov 13 01:50", Target: "usr/lib"},
		{Name: "null", Type: "other", Mode: "crw-rw-rw-", Time: "Nov 13 01:50"},
		{Name: "iso", Type: "file", Size: 5, Mode: "-rw-r--r--", Time: "2026-11-13 01:50"},
	}
	if len(es) != len(want) {
		t.Fatalf("got %d entries: %+v", len(es), es)
	}
	for i := range want {
		if es[i] != want[i] {
			t.Errorf("entry %d: %+v, want %+v", i, es[i], want[i])
		}
	}
}
