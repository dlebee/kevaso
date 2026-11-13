package kvoplugin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type entry struct {
	name, body, link string
	typ              byte
	mode             int64
}

func tarGz(t *testing.T, es ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link, Size: int64(len(e.body))}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func unpackTar(t *testing.T, b []byte) (string, error) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "files")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return root, UnpackTarGz(bytes.NewReader(b), root)
}

func TestUnpackAnAppBundle(t *testing.T) {
	root, err := unpackTar(t, tarGz(t,
		entry{name: "Kevaso Panes.app/", typ: tar.TypeDir},
		entry{name: "Kevaso Panes.app/Contents/Info.plist", body: "<plist/>"},
		entry{name: "./Kevaso Panes.app/Contents/MacOS/KevasoPanes", body: "#!/bin/sh\n", mode: 0o755},
		entry{name: "Kevaso Panes.app/Contents/Resources/Current", typ: tar.TypeSymlink, link: "../Info.plist"},
	))
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(root, "Kevaso Panes.app", "Contents", "MacOS", "KevasoPanes"))
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755) {
		t.Fatalf("entry point: %v %v", fi, err)
	}
	if b, err := os.ReadFile(filepath.Join(root, "Kevaso Panes.app", "Contents", "Resources", "Current")); err != nil || string(b) != "<plist/>" {
		t.Fatalf("link inside: %q %v", b, err)
	}
}

func unpackTarArgs(t *testing.T, es ...entry) error {
	t.Helper()
	_, err := unpackTar(t, tarGz(t, es...))
	return err
}

func TestUnpackRefusesWhatLeavesTheFolder(t *testing.T) {
	outside := t.TempDir()
	for name, es := range map[string][]entry{
		"dot-dot":        {{name: "../evil", body: "x"}},
		"dot-dot inside": {{name: "a/../../evil", body: "x"}},
		"absolute":       {{name: "/tmp/evil", body: "x"}},
		"backslash":      {{name: `a\..\..\evil`, body: "x"}},
		"drive":          {{name: "C:evil", body: "x"}},
		"control char":   {{name: "a\x01b", body: "x"}},
		"link absolute":  {{name: "l", typ: tar.TypeSymlink, link: outside}},
		"link up":        {{name: "a/l", typ: tar.TypeSymlink, link: "../../x"}},
		"link dangling":  {{name: "l", typ: tar.TypeSymlink, link: "nothing-here"}},
		// a link that looks inside on paper, but resolves through another link to the parent
		"link through link": {
			{name: "a/b/", typ: tar.TypeDir},
			{name: "a/b/s", typ: tar.TypeSymlink, link: "."},
			{name: "a/b/l", typ: tar.TypeSymlink, link: "s/../../.."},
		},
		"write through link": {
			{name: "d", typ: tar.TypeSymlink, link: "."},
			{name: "d/x", body: "x"},
		},
		"hard link":  {{name: "f", body: "x"}, {name: "h", typ: tar.TypeLink, link: "f"}},
		"device":     {{name: "dev", typ: tar.TypeChar}},
		"fifo":       {{name: "p", typ: tar.TypeFifo}},
		"twice":      {{name: "f", body: "x"}, {name: "f", body: "y"}},
		"under file": {{name: "f", body: "x"}, {name: "f/g", body: "y"}},
	} {
		if runtime.GOOS == "windows" && strings.HasPrefix(name, "link") {
			continue
		}
		if err := unpackTarArgs(t, es...); err == nil {
			t.Errorf("%s: unpacked", name)
		}
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("something landed outside: %v", ents)
	}
}

func TestUnpackLimits(t *testing.T) {
	saveB, saveF := limitUnpacked, limitFiles
	defer func() { limitUnpacked, limitFiles = saveB, saveF }()
	limitUnpacked, limitFiles = 10, 3
	if err := unpackTarArgs(t, entry{name: "big", body: strings.Repeat("x", 11)}); err == nil || !strings.Contains(err.Error(), "more than 10 bytes") {
		t.Errorf("size: %v", err)
	}
	if err := unpackTarArgs(t, entry{name: "a", body: "123456"}, entry{name: "b", body: "123456"}); err == nil {
		t.Error("total size over the limit unpacked")
	}
	if err := unpackTarArgs(t, entry{name: "a"}, entry{name: "b"}, entry{name: "c"}, entry{name: "d"}); err == nil || !strings.Contains(err.Error(), "more than 3 files") {
		t.Errorf("files: %v", err)
	}
	if err := unpackTarArgs(t, entry{name: "a", body: "1234567890"}); err != nil {
		t.Errorf("exactly the limit: %v", err)
	}
}

func zipFile(t *testing.T, es ...entry) *os.File {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range es {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		switch e.typ {
		case tar.TypeSymlink:
			h.SetMode(fs.ModeSymlink | 0o777)
			e.body = e.link
		case tar.TypeDir:
			h.SetMode(fs.ModeDir | 0o755)
		default:
			h.SetMode(0o755)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(e.body))
	}
	_ = zw.Close()
	p := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestUnpackZip(t *testing.T) {
	root := t.TempDir()
	if err := UnpackZip(zipFile(t, entry{name: "app/", typ: tar.TypeDir}, entry{name: "app/kvo-x.exe", body: "MZ"}), root); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "app", "kvo-x.exe")); string(b) != "MZ" {
		t.Fatalf("got %q", b)
	}
	for name, es := range map[string][]entry{
		"dot-dot":  {{name: "../evil", body: "x"}},
		"absolute": {{name: "/evil", body: "x"}},
		"link out": {{name: "l", typ: tar.TypeSymlink, link: "../../etc"}},
	} {
		if err := UnpackZip(zipFile(t, es...), t.TempDir()); err == nil {
			t.Errorf("%s: unpacked", name)
		}
	}
	saveB := limitUnpacked
	defer func() { limitUnpacked = saveB }()
	limitUnpacked = 1000
	// a zip bomb: tiny compressed, big inflated; counted as inflated
	if err := UnpackZip(zipFile(t, entry{name: "bomb", body: strings.Repeat("0", 100000)}), t.TempDir()); err == nil {
		t.Error("zip bomb unpacked")
	}
}
