package transfer

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"kevaso.com/core/api/client"
)

// Silo is one silo's files, through the API's file stream (tar and ls run in the silo).
type Silo struct {
	C               *client.Client
	Namespace, Name string
	Limit           int64 // most bytes one copy moves (DefaultLimit if 0)
}

func (s Silo) limit() int64 {
	if s.Limit > 0 {
		return s.Limit
	}
	return DefaultLimit
}

// capped keeps the first 64 KiB written to it (a command's stderr).
type capped struct{ b []byte }

func (c *capped) Write(p []byte) (int, error) {
	if room := 64<<10 - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// run runs op on p; stdin, if set, writes the command's input.
func (s Silo) run(ctx context.Context, op, p string, stdin func(io.Writer) error, stdout io.Writer) (int, string, error) {
	sess, err := s.C.OpenFiles(ctx, s.Namespace, s.Name, op, p)
	if err != nil {
		return -1, "", err
	}
	defer func() { _ = sess.Close() }()
	inErr := make(chan error, 1)
	go func() {
		var err error
		if stdin != nil {
			if err = stdin(sess); err != nil {
				_ = sess.Close() // don't let a half-written archive be unpacked as if whole
			}
		}
		_ = sess.CloseStdin()
		inErr <- err
	}()
	var errb capped
	code, err := sess.Wait(stdout, &errb)
	_ = sess.Close() // unblocks the input if the command stopped without reading it
	if e := <-inErr; e != nil && (err != nil || code == 0) {
		return code, string(errb.b), e // the input went wrong (over the limit…), not the command
	}
	return code, string(errb.b), err
}

func (s Silo) fail(tool string, code int, stderr string) error {
	if ToolMissing(code, stderr, tool) {
		return fmt.Errorf("silo/%s has no %s in its image: files are copied with the silo's own %s, and Kevaso installs nothing in silos", s.Name, tool, tool)
	}
	return fmt.Errorf("%s in silo/%s: exit %d: %s", tool, s.Name, code, strings.TrimSpace(stderr))
}

// Stat describes p in the silo; ok is false if there's nothing there.
func (s Silo) Stat(ctx context.Context, p string) (e Entry, ok bool, err error) {
	var out strings.Builder
	code, stderr, err := s.run(ctx, client.FileStat, p, nil, &out)
	if err != nil {
		return e, false, err
	}
	if code != 0 {
		if !ToolMissing(code, stderr, "ls") && strings.Contains(strings.ToLower(stderr), "no such file") {
			return e, false, nil
		}
		return e, false, s.fail("ls", code, stderr)
	}
	es := ParseLs(out.String())
	if len(es) != 1 {
		return e, false, fmt.Errorf("ls %s in silo/%s: %q", p, s.Name, out.String())
	}
	return es[0], true, nil
}

// List lists the folder p.
func (s Silo) List(ctx context.Context, p string) ([]Entry, error) {
	var out strings.Builder
	code, stderr, err := s.run(ctx, client.FileList, p, nil, &out)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, s.fail("ls", code, stderr)
	}
	return ParseLs(out.String()), nil
}

// ReadTar writes a tar of p (entries ./BASE…) to w.
func (s Silo) ReadTar(ctx context.Context, p string, w io.Writer) error {
	code, stderr, err := s.run(ctx, client.FileRead, p, nil, w)
	if err != nil {
		return err
	}
	if code != 0 {
		return s.fail("tar", code, stderr)
	}
	return nil
}

// WriteTar unpacks the tar pack writes into the silo's folder dir.
func (s Silo) WriteTar(ctx context.Context, dir string, pack func(io.Writer) error) error {
	code, stderr, err := s.run(ctx, client.FileWrite, dir, pack, io.Discard)
	if err != nil {
		return err
	}
	if code != 0 {
		return s.fail("tar", code, stderr)
	}
	return nil
}

// Download copies p (a file or folder) from the silo to localDir/name.
func (s Silo) Download(ctx context.Context, p, localDir, name string) (Result, error) {
	p = path.Clean(p)
	from := path.Base(p)
	if p == "/" {
		from = ""
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := io.Pipe()
	type out struct {
		res Result
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := Unpack(pr, localDir, from, name, s.limit())
		if err != nil {
			cancel() // stop the download
		}
		_, _ = io.Copy(io.Discard, pr)
		done <- out{res, err}
	}()
	err := s.ReadTar(ctx, p, pw)
	_ = pw.CloseWithError(err)
	o := <-done
	if o.err != nil { // what went wrong here comes first: the download stopped because of it
		return o.res, o.err
	}
	return o.res, err
}

// Upload copies the local src (a file or folder) to the silo as dir/name.
func (s Silo) Upload(ctx context.Context, src, dir, name string) (Result, error) {
	var res Result
	err := s.WriteTar(ctx, dir, func(w io.Writer) error {
		var err error
		res, err = Pack(w, src, name, s.limit())
		return err
	})
	return res, err
}
