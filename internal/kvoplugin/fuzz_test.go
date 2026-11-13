package kvoplugin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzUnpackTarGz: a plugin's archive is the publisher's, and kvo unpacks it before running
// anything. Whatever its entries (files, folders, links, hard links; any names and targets, in any
// order), nothing is ever written outside the plugin's folder, and an archive that unpacks has no
// link leading out of it.
//
// The input is the archive's entries, one per line: TYPE NAME [TARGET], TYPE one of f d l h.
//
//	go test ./internal/kvoplugin -run '^$' -fuzz FuzzUnpackTarGz -fuzztime 60s
func FuzzUnpackTarGz(f *testing.F) {
	for _, s := range []string{
		"f kvo-x\nd lib\nf lib/a.so",
		"l up ..\nf up/escaped",
		"l a b\nl b ../..\nf a/x",
		"d sub\nl sub/up ../..\nf sub/up/x",
		"l x /etc\nf x/passwd",
		"f ../x",
		"f ./a/../../x",
		"h hard /etc/passwd",
		"l a sub\nd sub\nf a/x",
		"l link .\nf link/link/x",
		"f a\nf a",
		"l A ..\nf a/x",
		"f a\\..\\..\\x",
		"l l c:/windows",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for i, line := range strings.Split(spec, "\n") {
			if i >= 6 {
				break
			}
			parts := strings.SplitN(line, " ", 3)
			if len(parts) < 2 || parts[1] == "" {
				continue
			}
			h := &tar.Header{Name: parts[1], Mode: 0o644}
			if len(parts) == 3 {
				h.Linkname = parts[2]
			}
			switch parts[0] {
			case "f":
				h.Typeflag, h.Size = tar.TypeReg, 1
			case "d":
				h.Typeflag, h.Mode = tar.TypeDir, 0o755
			case "l":
				h.Typeflag = tar.TypeSymlink
			case "h":
				h.Typeflag = tar.TypeLink
			default:
				continue
			}
			if tw.WriteHeader(h) != nil {
				return
			}
			if h.Typeflag == tar.TypeReg {
				_, _ = tw.Write([]byte("x"))
			}
		}
		_ = tw.Close()
		_ = gz.Close()

		outer := t.TempDir()
		root := filepath.Join(outer, "plugin")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		err := UnpackTarGz(&buf, root)
		entries, _ := os.ReadDir(outer)
		if len(entries) != 1 || entries[0].Name() != "plugin" {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("%q wrote outside the plugin's folder: %v (unpack: %v)", spec, names, err)
		}
		if err != nil {
			return
		}
		realRoot, _ := filepath.EvalSymlinks(root)
		_ = filepath.Walk(root, func(p string, fi os.FileInfo, werr error) error {
			if werr != nil || fi.Mode()&os.ModeSymlink == 0 {
				return nil
			}
			got, err := filepath.EvalSymlinks(p)
			if err != nil {
				t.Fatalf("%q unpacked with a dangling link %s", spec, p)
			}
			if rel, err := filepath.Rel(realRoot, got); err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
				t.Fatalf("%q unpacked with %s leading out to %s", spec, p, got)
			}
			return nil
		})
	})
}

// FuzzVerifyIndex: an index is read only once its signature holds, and a signed one is accepted
// only when every name, version, platform and entry in it is valid. A broken or hostile
// publisher can't get an entry point that leaves the plugin's folder past this.
//
//	go test ./internal/kvoplugin -run '^$' -fuzz FuzzVerifyIndex -fuzztime 60s
func FuzzVerifyIndex(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	good := `{"apiVersion":"` + APIVersion + `","name":"acme","generated":"2026-11-13T00:00:00Z","plugins":[{"name":"whoami","versions":[{"version":"v1.0.0","platforms":[{"os":"linux","arch":"amd64","url":"whoami.tar.gz","sha256":"` + strings.Repeat("a", 64) + `","kind":"tar.gz","entry":"bin/kvo-whoami"}]}]}]}`
	for _, s := range []string{good, strings.Replace(good, "bin/kvo-whoami", "../kvo-whoami", 1), strings.Replace(good, "whoami", "Who Am I", 1),
		strings.Replace(good, `"tar.gz","entry"`, `"binary","entry"`, 1), `{}`, `[]`, `null`} {
		f.Add([]byte(s), true)
		f.Add([]byte(s), false)
	}
	f.Fuzz(func(t *testing.T, doc []byte, signed bool) {
		key := priv
		if !signed {
			key = other
		}
		ix, err := Verify(doc, Sign(key, doc), pub)
		if !signed {
			if err == nil {
				t.Fatal("an index signed by another key was accepted")
			}
			return
		}
		if err != nil {
			return
		}
		for _, p := range ix.Plugins {
			if !ValidName(p.Name) {
				t.Fatalf("accepted plugin name %q", p.Name)
			}
			for _, v := range p.Versions {
				for _, a := range v.Platforms {
					if a.Kind != KindBinary {
						if _, err := cleanRel(a.Entry); err != nil {
							t.Fatalf("accepted entry %q", a.Entry)
						}
					}
				}
			}
		}
	})
}
