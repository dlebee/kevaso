package exec

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

var validName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// Discover finds the programs in dir, by file name: /etc/kevaso/dns-providers/cloudflare is the DNS
// provider "cloudflare". The control plane runs them as root, so dir and every program must belong
// to root (or to whoever runs the control plane) and be writable by no one else; anything else is
// refused, not skipped. A missing dir is no programs.
func Discover(dir string) (map[string]string, error) {
	if err := trusted(dir, true); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.Name()[0] == '.' {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if !validName.MatchString(e.Name()) {
			return nil, fmt.Errorf("%s: names are lowercase letters, digits and dashes", p)
		}
		if err := trusted(p, false); err != nil {
			return nil, err
		}
		out[e.Name()] = p
	}
	return out, nil
}

func trusted(p string, dir bool) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	switch {
	case dir && !fi.IsDir():
		return fmt.Errorf("%s: not a directory", p)
	case !dir && !fi.Mode().IsRegular():
		return fmt.Errorf("%s: not a regular file", p)
	case !dir && fi.Mode().Perm()&0o100 == 0:
		return fmt.Errorf("%s: not executable", p)
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s: writable by group or others (chmod go-w)", p)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s: owned by uid %d, not root", p, st.Uid)
	}
	return nil
}
