// Package transfer packs and unpacks the tar streams `kvo cp` and `kvo ui` exchange with a silo's
// tar (nothing is installed in the silo). Unpacking on this machine trusts nothing in the stream:
// every write stays under the destination folder (os.Root), names that climb out of it end the
// copy, links pointing outside it are skipped, and the total size is capped.
package transfer

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// DefaultLimit is the most a copy moves unless the user says otherwise (--max-size).
const DefaultLimit = 1 << 30

// ErrTooBig: the copy is over its size limit.
var ErrTooBig = errors.New("over the size limit")

// Result says what a copy did.
type Result struct {
	Files, Dirs, Links int
	Bytes              int64
	Skipped            []string // entries not written, and why
}

// Pack writes a tar of src (a file or a folder; links are kept as links, devices and the like are
// skipped) whose top entry is named name. Owners are left out: files belong to whoever unpacks.
func Pack(w io.Writer, src, name string, limit int64) (Result, error) {
	var res Result
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return res, fmt.Errorf("%q: want a plain file name", name)
	}
	tw := tar.NewWriter(w)
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		entry := path.Join(name, filepath.ToSlash(rel))
		fi, err := d.Info()
		if err != nil {
			return err
		}
		link := ""
		switch {
		case fi.Mode().IsRegular(), fi.IsDir():
		case fi.Mode()&fs.ModeSymlink != 0:
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		default:
			res.Skipped = append(res.Skipped, entry+": not a file, folder or link")
			return nil
		}
		hdr, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		hdr.Name, hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname = entry, 0, 0, "", ""
		hdr.Format = tar.FormatPAX
		if fi.IsDir() {
			hdr.Name += "/"
		}
		if hdr.Typeflag == tar.TypeReg {
			if res.Bytes+hdr.Size > limit {
				return fmt.Errorf("%s: %w of %d bytes", entry, ErrTooBig, limit)
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			if _, err := io.CopyN(tw, f, hdr.Size); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			res.Files++
			res.Bytes += hdr.Size
		case tar.TypeDir:
			res.Dirs++
		case tar.TypeSymlink:
			res.Links++
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	return res, tw.Close()
}

// Unpack reads a tar made by a silo's tar (entries "./FROM", "./FROM/…"; with FROM "", every
// entry, as from the silo's "/") into dir, with FROM renamed to name.
func Unpack(r io.Reader, dir, from, name string, limit int64) (Result, error) {
	var res Result
	if name == "" || strings.ContainsAny(name, "/\x00") || !filepath.IsLocal(name) {
		return res, fmt.Errorf("%q: want a plain file name", name)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return res, err
	}
	defer func() { _ = root.Close() }()
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return res, nil
		}
		if err != nil {
			return res, err
		}
		rel, err := localName(hdr.Name, from, name)
		if err != nil {
			return res, err
		}
		perm := hdr.FileInfo().Mode().Perm()
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(rel, perm|0o700); err != nil {
				return res, err
			}
			res.Dirs++
		case tar.TypeReg:
			if hdr.Size < 0 || res.Bytes+hdr.Size > limit {
				return res, fmt.Errorf("%s: %w of %d bytes", hdr.Name, ErrTooBig, limit)
			}
			if err := mkParent(root, rel); err != nil {
				return res, err
			}
			_ = root.Remove(rel) // a link there is replaced, never written through
			f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm|0o600)
			if err != nil {
				return res, err
			}
			_, err = io.CopyN(f, tr, hdr.Size)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return res, fmt.Errorf("%s: %w", rel, err)
			}
			res.Files++
			res.Bytes += hdr.Size
		case tar.TypeSymlink:
			t := hdr.Linkname
			if path.IsAbs(t) || !filepath.IsLocal(filepath.Join(filepath.Dir(rel), filepath.FromSlash(t))) {
				res.Skipped = append(res.Skipped, rel+": a link to "+t+", outside the copy")
				continue
			}
			if err := mkParent(root, rel); err != nil {
				return res, err
			}
			_ = root.Remove(rel)
			if err := root.Symlink(t, rel); err != nil {
				return res, err
			}
			res.Links++
		default:
			res.Skipped = append(res.Skipped, rel+": not a file, folder or link")
		}
	}
}

// localName maps an entry from the silo to a path under the destination, refusing any that climbs
// out of it (absolute, "..", or outside FROM).
func localName(entry, from, name string) (string, error) {
	bad := fmt.Errorf("refusing %q: it isn't inside what was copied", entry)
	if strings.HasPrefix(entry, "/") || strings.ContainsRune(entry, 0) || strings.Contains(entry, "\\") {
		return "", bad
	}
	for _, part := range strings.Split(entry, "/") {
		if part == ".." {
			return "", bad
		}
	}
	p := path.Clean(strings.TrimPrefix(entry, "./"))
	var rel string
	switch {
	case from == "":
		rel = path.Join(name, p)
	case p == from:
		rel = name
	case strings.HasPrefix(p, from+"/"):
		rel = path.Join(name, strings.TrimPrefix(p, from+"/"))
	default:
		return "", bad
	}
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return "", bad
	}
	return filepath.FromSlash(rel), nil
}

func mkParent(root *os.Root, rel string) error {
	if d := filepath.Dir(rel); d != "." {
		return root.MkdirAll(d, 0o755)
	}
	return nil
}

// FirstFile reads a tar up to its first regular file and copies that file's content to w (at most
// limit bytes): a download of one file from the silo, without unpacking anything.
func FirstFile(r io.Reader, w io.Writer, limit int64) (*tar.Header, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("not a file")
			}
			return nil, err
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			if hdr.Size > limit {
				return hdr, fmt.Errorf("%s: %w of %d bytes", hdr.Name, ErrTooBig, limit)
			}
			_, err := io.CopyN(w, tr, hdr.Size)
			return hdr, err
		case tar.TypeDir:
			return hdr, errors.New("a folder, not a file")
		}
	}
}

// OneFile writes a tar holding one file, name, of size bytes from r: an upload from the browser.
func OneFile(w io.Writer, name string, size int64, r io.Reader) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("%q: want a plain file name", name)
	}
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return err
	}
	if _, err := io.CopyN(tw, r, size); err != nil {
		return err
	}
	return tw.Close()
}
