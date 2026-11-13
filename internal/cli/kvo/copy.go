package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/transfer"
)

// siloPath reads silo/NAME:/PATH (or silos/NAME:…).
func siloPath(s string) (name, p string, ok bool) {
	rest, found := strings.CutPrefix(s, "silo/")
	if !found {
		if rest, found = strings.CutPrefix(s, "silos/"); !found {
			return "", "", false
		}
	}
	name, p, ok = strings.Cut(rest, ":")
	return name, p, ok && name != ""
}

func (o opts) limit() (int64, error) {
	if o.term.maxSize == "" {
		return transfer.DefaultLimit, nil
	}
	return transfer.ParseSize(o.term.maxSize)
}

// copyFiles is `kvo cp SRC DST`: one side is silo/NAME:/PATH, the other a local path. Like cp: a
// destination that is a folder gets SRC inside it, anything else is SRC's new name.
func copyFiles(ctx context.Context, c *client.Client, o opts, stdout, stderr io.Writer) error {
	usage := errors.New("cp needs SRC DST, one of them silo/NAME:/PATH (kvo cp ./app silo/web:/srv/, kvo cp silo/web:/var/log ./logs)")
	if len(o.args) != 2 {
		return usage
	}
	limit, err := o.limit()
	if err != nil {
		return err
	}
	sn, sp, fromSilo := siloPath(o.args[0])
	dn, dp, toSilo := siloPath(o.args[1])
	if fromSilo == toSilo {
		return usage
	}
	var res transfer.Result
	var where string
	if fromSilo {
		if !path.IsAbs(sp) {
			return fmt.Errorf("%s: the path in the silo must be absolute", o.args[0])
		}
		s := transfer.Silo{C: c, Namespace: defaultNS(o), Name: sn, Limit: limit}
		dst := o.args[1]
		dir, name := filepath.Dir(dst), filepath.Base(dst)
		if fi, err := os.Stat(dst); err == nil && fi.IsDir() {
			dir, name = dst, path.Base(path.Clean(sp))
			if path.Clean(sp) == "/" {
				return errors.New("copying the silo's / needs the name of a new local folder to hold it")
			}
		}
		where = filepath.Join(dir, name)
		res, err = s.Download(ctx, sp, dir, name)
		if err != nil {
			return err
		}
	} else {
		if !path.IsAbs(dp) {
			return fmt.Errorf("%s: the path in the silo must be absolute", o.args[1])
		}
		src := o.args[0]
		if _, err := os.Lstat(src); err != nil {
			return err
		}
		s := transfer.Silo{C: c, Namespace: defaultNS(o), Name: dn, Limit: limit}
		dir, name := path.Dir(path.Clean(dp)), path.Base(path.Clean(dp))
		if strings.HasSuffix(dp, "/") || path.Clean(dp) == "/" {
			dir, name = path.Clean(dp), filepath.Base(filepath.Clean(src))
		} else if e, ok, err := s.Stat(ctx, dp); err != nil {
			return err
		} else if ok && e.Type == "dir" {
			dir, name = path.Clean(dp), filepath.Base(filepath.Clean(src))
		}
		where = "silo/" + dn + ":" + path.Join(dir, name)
		res, err = s.Upload(ctx, src, dir, name)
		if err != nil {
			return err
		}
	}
	for _, sk := range res.Skipped {
		_, _ = fmt.Fprintln(stderr, "kvo: skipped", sk)
	}
	_, _ = fmt.Fprintf(stdout, "%s: %d files, %d folders, %d links, %d bytes\n", where, res.Files, res.Dirs, res.Links, res.Bytes)
	return nil
}
