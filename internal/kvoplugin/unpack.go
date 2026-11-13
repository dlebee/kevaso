package kvoplugin

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Limits on what kvo fetches and unpacks for one plugin.
const (
	MaxDownload = 256 << 20 // the artifact as downloaded
	MaxUnpacked = 1 << 30   // everything an archive unpacks to
	MaxFiles    = 20000     // entries in an archive
	maxLinkLen  = 1024
)

// The limits unpacking enforces (tests lower them).
var (
	limitUnpacked int64 = MaxUnpacked
	limitFiles          = MaxFiles
)

// cleanRel checks an archive entry's name (or an index's entry point): relative, forward slashes,
// no empty, "." or ".." part, no control characters or backslashes, no drive letter.
func cleanRel(name string) (string, error) {
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimSuffix(name, "/")
	if name == "" || len(name) > 1024 {
		return "", fmt.Errorf("bad path %q", name)
	}
	if strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\:") {
		return "", fmt.Errorf("path %q isn't relative", name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("path %q has a control character", name)
		}
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("path %q leaves its folder", name)
		}
	}
	return name, nil
}

// unpacker writes entries under root, which it created empty, and nowhere else.
type unpacker struct {
	root  string
	files int
	bytes int64
	links []string
}

// parent makes the folders above rel and refuses to write through a link the archive made.
func (u *unpacker) parent(rel string) error {
	dir := path.Dir(rel)
	if dir == "." {
		return nil
	}
	cur := u.root
	for _, part := range strings.Split(dir, "/") {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := os.Mkdir(cur, 0o755); err != nil {
				return err
			}
		case err != nil:
			return err
		case fi.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("%s is written through a link", rel)
		case !fi.IsDir():
			return fmt.Errorf("%s is under a file", rel)
		}
	}
	return nil
}

func (u *unpacker) count() error {
	u.files++
	if u.files > limitFiles {
		return fmt.Errorf("more than %d files", limitFiles)
	}
	return nil
}

func (u *unpacker) dir(name string) error {
	rel, err := cleanRel(name)
	if err != nil {
		return err
	}
	if err := u.count(); err != nil {
		return err
	}
	if err := u.parent(rel + "/x"); err != nil {
		return err
	}
	return nil
}

func (u *unpacker) file(name string, mode fs.FileMode, r io.Reader) error {
	rel, err := cleanRel(name)
	if err != nil {
		return err
	}
	if err := u.count(); err != nil {
		return err
	}
	if err := u.parent(rel); err != nil {
		return err
	}
	perm := fs.FileMode(0o644)
	if mode&0o111 != 0 {
		perm = 0o755
	}
	f, err := os.OpenFile(filepath.Join(u.root, filepath.FromSlash(rel)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s is in the archive twice", rel)
		}
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r, limitUnpacked-u.bytes+1))
	u.bytes += n
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if u.bytes > limitUnpacked {
		return fmt.Errorf("unpacks to more than %d bytes", limitUnpacked)
	}
	return nil
}

func (u *unpacker) link(name, target string) error {
	rel, err := cleanRel(name)
	if err != nil {
		return err
	}
	if err := u.count(); err != nil {
		return err
	}
	if target == "" || len(target) > maxLinkLen || strings.HasPrefix(target, "/") || strings.ContainsAny(target, "\\:\x00") {
		return fmt.Errorf("link %s → %q leaves the plugin's folder", rel, target)
	}
	if t := path.Join(path.Dir(rel), target); t == ".." || strings.HasPrefix(t, "../") {
		return fmt.Errorf("link %s → %q leaves the plugin's folder", rel, target)
	}
	if err := u.parent(rel); err != nil {
		return err
	}
	if err := os.Symlink(filepath.FromSlash(target), filepath.Join(u.root, filepath.FromSlash(rel))); err != nil {
		return err
	}
	u.links = append(u.links, rel)
	return nil
}

// checkLinks resolves every link for real once everything is written: each must land inside root
// (links through links can't climb out either) and not dangle.
func (u *unpacker) checkLinks() error {
	root, err := filepath.EvalSymlinks(u.root)
	if err != nil {
		return err
	}
	for _, rel := range u.links {
		got, err := filepath.EvalSymlinks(filepath.Join(u.root, filepath.FromSlash(rel)))
		if err != nil {
			return fmt.Errorf("link %s: %w", rel, err)
		}
		if r, err := filepath.Rel(root, got); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return fmt.Errorf("link %s leaves the plugin's folder", rel)
		}
	}
	return nil
}

// UnpackTarGz unpacks a gzipped tar into root (an empty folder): regular files, folders and links
// that stay inside; anything else (hard links, devices) is refused, and so is the whole archive.
func UnpackTarGz(r io.Reader, root string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	u := &unpacker{root: root}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			err = u.dir(h.Name)
		case tar.TypeReg:
			err = u.file(h.Name, fs.FileMode(h.Mode), tr)
		case tar.TypeSymlink:
			err = u.link(h.Name, h.Linkname)
		default:
			err = fmt.Errorf("%s: only files, folders and links inside are allowed", h.Name)
		}
		if err != nil {
			return err
		}
	}
	return u.checkLinks()
}

// UnpackZip unpacks a zip file into root, with UnpackTarGz's rules.
func UnpackZip(f *os.File, root string) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return err
	}
	if len(zr.File) > limitFiles {
		return fmt.Errorf("more than %d files", limitFiles)
	}
	u := &unpacker{root: root}
	for _, zf := range zr.File {
		m := zf.Mode()
		switch {
		case m.IsDir():
			err = u.dir(zf.Name)
		case m&fs.ModeSymlink != 0:
			var target []byte
			if target, err = readZip(zf, maxLinkLen); err == nil {
				err = u.link(zf.Name, string(target))
			}
		case m.IsRegular():
			var rc io.ReadCloser
			if rc, err = zf.Open(); err == nil {
				err = u.file(zf.Name, m, rc)
				_ = rc.Close()
			}
		default:
			err = fmt.Errorf("%s: only files, folders and links inside are allowed", zf.Name)
		}
		if err != nil {
			return err
		}
	}
	return u.checkLinks()
}

func readZip(zf *zip.File, limit int64) ([]byte, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("%s: link too long", zf.Name)
	}
	return b, err
}
