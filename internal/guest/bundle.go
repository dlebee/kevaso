package guest

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "kevaso.com/core/api/v1"
)

// HTML pane bundles (ADR 0007, v1.PaneBundleMaxBytes): what `pane html --bundle` uploads. Built
// and checked here, in the silo; the control plane never opens one.

// ReadBundle is the bundle for path: a folder packed (PackBundle), a ustar archive checked by the
// format's rules, or any other file as the pane's index.html.
func ReadBundle(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return PackBundle(path)
	}
	if st.Size() > v1.PaneBundleMaxBytes {
		return nil, fmt.Errorf("bundle %s: %d bytes, more than %d", path, st.Size(), v1.PaneBundleMaxBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if isTar(b) {
		if err := CheckBundle(b); err != nil {
			return nil, fmt.Errorf("bundle %s: %w", path, err)
		}
	}
	return b, nil
}

func isTar(b []byte) bool { return len(b) >= 512 && string(b[257:262]) == "ustar" }

// bundleName: a name the panes app accepts.
func bundleName(name string) error {
	parts := strings.Split(name, "/")
	if name == "" || len(name) >= 256 || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) ||
		strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("bad path %.60q", name)
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return fmt.Errorf("bad path %.60q", name)
		}
	}
	return nil
}

// PackBundle packs a folder holding index.html into a bundle: a ustar archive with its files and
// folders in sorted order, times at the epoch, no owners, modes 0644 and 0755. Links and other
// special files are refused, not followed.
func PackBundle(dir string) ([]byte, error) {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	files, total, index := 0, int64(0), false
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error { // lexical order
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		name := filepath.ToSlash(rel)
		if err := bundleName(name); err != nil {
			return err
		}
		h := &tar.Header{Name: name, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		switch t := d.Type(); {
		case t.IsDir():
			h.Name, h.Typeflag, h.Mode = name+"/", tar.TypeDir, 0o755
		case t.IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			files++
			total += info.Size()
			if files > v1.PaneBundleMaxFiles {
				return fmt.Errorf("more than %d files", v1.PaneBundleMaxFiles)
			}
			if total > v1.PaneBundleMaxUnpacked {
				return fmt.Errorf("more than %d bytes unpacked", v1.PaneBundleMaxUnpacked)
			}
			index = index || name == "index.html"
			h.Typeflag, h.Mode, h.Size = tar.TypeReg, 0o644, info.Size()
		default:
			return fmt.Errorf("%s is not a regular file or folder (%s)", name, t)
		}
		if err := w.WriteHeader(h); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if h.Typeflag == tar.TypeReg {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.CopyN(w, f, h.Size)
			_ = f.Close()
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		if buf.Len() > v1.PaneBundleMaxBytes {
			return fmt.Errorf("more than %d bytes packed", v1.PaneBundleMaxBytes)
		}
		return nil
	})
	if err == nil && !index {
		err = errors.New("no index.html at its top")
	}
	if err == nil {
		err = w.Close()
	}
	if err == nil && buf.Len() > v1.PaneBundleMaxBytes {
		err = fmt.Errorf("more than %d bytes packed", v1.PaneBundleMaxBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("bundle %s: %w", dir, err)
	}
	return buf.Bytes(), nil
}

// CheckBundle checks a ready-made archive by the format's rules, as the panes app will.
func CheckBundle(b []byte) error {
	r := tar.NewReader(bytes.NewReader(b))
	files, total, index := 0, int64(0), false
	seen := map[string]bool{}
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Go's reader applies pax and GNU long names; the panes app reads plain ustar only.
		if len(h.PAXRecords) > 0 || h.Format == tar.FormatGNU {
			return fmt.Errorf("%.60s: pax or GNU headers (the panes app reads plain ustar)", h.Name)
		}
		name := strings.TrimPrefix(h.Name, "./")
		switch h.Typeflag {
		case tar.TypeDir:
			if d := strings.TrimSuffix(name, "/"); d != "" && d != "." {
				if err := bundleName(d); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			if err := bundleName(name); err != nil {
				return err
			}
			if seen[name] {
				return fmt.Errorf("%s twice", name)
			}
			seen[name] = true
			files++
			total += h.Size
			if files > v1.PaneBundleMaxFiles {
				return fmt.Errorf("more than %d files", v1.PaneBundleMaxFiles)
			}
			if total > v1.PaneBundleMaxUnpacked {
				return fmt.Errorf("more than %d bytes unpacked", v1.PaneBundleMaxUnpacked)
			}
			index = index || name == "index.html"
		default:
			return fmt.Errorf("%.60s is not a regular file or folder (type %q)", name, h.Typeflag)
		}
	}
	if !index {
		return errors.New("no index.html at its top")
	}
	return nil
}
