package guest

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

func write(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ADR 0007: a folder becomes a ustar archive, the same bytes for the same files whatever their
// times, owners or modes, with sorted names and nothing but files and folders.
func TestPackBundleIsDeterministic(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	for _, d := range []string{a, b} {
		write(t, d, "index.html", "<script src=js/app.js></script>")
		write(t, d, "js/app.js", "draw()")
		write(t, d, "style.css", "canvas{}")
	}
	_ = os.Chtimes(filepath.Join(b, "js", "app.js"), time.Unix(1e9, 0), time.Unix(1e9, 0))
	_ = os.Chmod(filepath.Join(b, "style.css"), 0o755)
	pa, err := PackBundle(a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := PackBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pa, pb) {
		t.Fatal("the same files packed differently")
	}
	if string(pa[257:262]) != "ustar" {
		t.Fatalf("not ustar: %q", pa[257:265])
	}
	r := tar.NewReader(bytes.NewReader(pa))
	var names []string
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || !h.ModTime.Equal(time.Unix(0, 0)) || h.Format != tar.FormatUSTAR {
			t.Errorf("%s: %+v", h.Name, h)
		}
		if (h.Typeflag == tar.TypeReg && h.Mode != 0o644) || (h.Typeflag == tar.TypeDir && h.Mode != 0o755) {
			t.Errorf("%s: mode %o", h.Name, h.Mode)
		}
		names = append(names, h.Name)
	}
	if got := strings.Join(names, " "); got != "index.html js/ js/app.js style.css" {
		t.Fatalf("entries %q", got)
	}
}

func TestPackBundleRefuses(t *testing.T) {
	noIndex := t.TempDir()
	write(t, noIndex, "main.html", "<p>")
	link := t.TempDir()
	write(t, link, "index.html", "<p>")
	if err := os.Symlink("/etc/passwd", filepath.Join(link, "passwd")); err != nil {
		t.Fatal(err)
	}
	big := t.TempDir()
	write(t, big, "index.html", "<p>")
	write(t, big, "blob.bin", strings.Repeat("x", v1.PaneBundleMaxBytes))
	many := t.TempDir()
	write(t, many, "index.html", "<p>")
	for i := range v1.PaneBundleMaxFiles {
		write(t, many, filepath.Join("f", strings.Repeat("a", i%50+1)+string(rune('a'+i/50))), "")
	}
	for name, c := range map[string]struct {
		dir, msg string
	}{
		"no index.html": {noIndex, "index.html"},
		"a link":        {link, "not a regular file or folder"},
		"too large":     {big, "more than"},
		"too many":      {many, "files"},
	} {
		if _, err := PackBundle(c.dir); err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: %v, want %q", name, err, c.msg)
		}
	}
}

// A ready-made archive is checked by the same rules before it's uploaded; anything else is the
// pane's index.html as it is.
func TestBundleFileChecksArchives(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	_ = w.WriteHeader(&tar.Header{Name: "../escape.html", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR})
	_, _ = w.Write([]byte("x"))
	_ = w.Close()
	bad := filepath.Join(dir, "bad.tar")
	_ = os.WriteFile(bad, buf.Bytes(), 0o600)
	if _, err := ReadBundle(bad); err == nil || !strings.Contains(err.Error(), "bad path") {
		t.Errorf("an archive escaping its folder: %v", err)
	}
	html := filepath.Join(dir, "pane.html")
	_ = os.WriteFile(html, []byte("<canvas></canvas>"), 0o600)
	if b, err := ReadBundle(html); err != nil || string(b) != "<canvas></canvas>" {
		t.Errorf("a single HTML file: %q %v", b, err)
	}
}

func TestPaneHTMLUploadsAFolder(t *testing.T) {
	f := &fakeBroker{answers: []client.BrokerResponse{{Digest: "sha256:" + strings.Repeat("a", 64)}, {}}}
	dir := t.TempDir()
	write(t, dir, "index.html", "<canvas></canvas>")
	var out, errs bytes.Buffer
	if err := run(context.Background(), f.dial, "/", []string{"pane", "html", "fleet", "--bundle", dir}, nil, &out, &errs); err != nil {
		t.Fatal(err)
	}
	want, _ := PackBundle(dir)
	if f.got[0].Op != client.OpPaneBundle || !bytes.Equal(f.got[0].Payload, want) {
		t.Fatalf("uploaded %d bytes, want the packed folder (%d)", len(f.got[0].Payload), len(want))
	}
}
