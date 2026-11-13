package ocienv

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

const (
	// Name is the name kevasod answers to as this runtime (its argv[0]'s base name).
	Name = "kevaso-oci"
	// ShimPath is where the container runtime's install links it, and what the engine is given.
	ShimPath = "/usr/local/lib/kevaso/" + Name
	// ConfigPath is the runtime's own configuration: the real runtime, written by the install.
	ConfigPath = "/etc/kevaso/oci-runtime.json"
	// RuntimeName is its name in the engine (docker's daemon.json runtimes, `--runtime`).
	RuntimeName = Name
	// Annotation carries the silo's short id: whose env file to read. Never a value.
	Annotation = "kevaso.com/env-secrets"
	// SecretsDir is where each silo's secrets tmpfs is (the container runtime's SecretsDir).
	SecretsDir = "/run/kevaso-secrets"
	// maxConfig bounds what's read of a bundle's config.json.
	maxConfig = 64 << 20
)

// Config is the runtime's own configuration file.
type Config struct {
	// Runtime is the real runtime's absolute path: what the engine ran before this one was put in
	// front of it (runc, from the install).
	Runtime string `json:"runtime"`
}

// shortID is a silo's short id, as the container runtime names its folders.
var shortID = regexp.MustCompile(`^[0-9a-f]{10}$`)

// Shim is the runtime with its surroundings, so tests can stand them in.
type Shim struct {
	ConfigPath string
	SecretsDir string
	Owner      int // who must own the configuration, the secrets folders and the env file (root)
	Stderr     io.Writer
	// Exec replaces this process with the real runtime (syscall.Exec).
	Exec func(path string, argv, env []string) error
	// InMemory reports whether path is on a filesystem in memory (tmpfs, ramfs) and its type.
	InMemory func(path string) (bool, string, error)
	// Self is this program, which the configuration must not name as the real runtime.
	Self string
}

// Main is kevasod called as kevaso-oci: args without argv[0]. It returns only on a failure (the
// exit code); otherwise it has become the real runtime.
func Main(args []string) int {
	self, _ := os.Executable()
	s := &Shim{ConfigPath: ConfigPath, SecretsDir: SecretsDir, Owner: 0, Stderr: os.Stderr, Exec: syscall.Exec, InMemory: inMemory, Self: self}
	return s.Run(args, os.Environ())
}

// Run does what Main says, with env as this process's environment (passed on as it is).
func (s *Shim) Run(args, env []string) int {
	inv, perr := Parse(args)
	real, err := s.realRuntime()
	if err == nil {
		err = perr
	}
	if err == nil && (inv.Action == "create" || inv.Action == "run") {
		err = s.prepare(inv)
	}
	if err != nil {
		s.fail(inv, err)
		return 1
	}
	if err := s.Exec(real, append([]string{real}, args...), env); err != nil {
		s.fail(inv, fmt.Errorf("exec %s: %w", real, err))
		return 1
	}
	return 0
}

// fail tells the engine why: on stderr, and in the runtime's log, where containerd's shim reads
// a create's error from. Never a value: errors here name files and variables only.
func (s *Shim) fail(inv Invocation, err error) {
	msg := Name + ": " + err.Error()
	_, _ = fmt.Fprintln(s.Stderr, msg)
	if inv.Log == "" {
		return
	}
	f, oerr := os.OpenFile(inv.Log, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if oerr != nil {
		return
	}
	defer func() { _ = f.Close() }()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if inv.LogFormat == "json" {
		line, _ := json.Marshal(map[string]string{"level": "error", "msg": msg, "time": now})
		_, _ = f.Write(append(line, '\n'))
		return
	}
	_, _ = fmt.Fprintf(f, "time=%q level=error msg=%q\n", now, msg)
}

// realRuntime reads the configuration: root's, not a link, writable by root only.
func (s *Shim) realRuntime() (string, error) {
	b, err := s.readStrict(s.ConfigPath, 0o022, 1<<16)
	if err != nil {
		return "", fmt.Errorf("its configuration: %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return "", fmt.Errorf("its configuration %s: %w", s.ConfigPath, err)
	}
	if !filepath.IsAbs(c.Runtime) || filepath.Clean(c.Runtime) != c.Runtime {
		return "", fmt.Errorf("its configuration %s: runtime %q isn't an absolute path", s.ConfigPath, c.Runtime)
	}
	if filepath.Base(c.Runtime) == Name || sameFile(c.Runtime, s.Self) {
		return "", fmt.Errorf("its configuration %s: the real runtime is this one", s.ConfigPath)
	}
	return c.Runtime, nil
}

func sameFile(a, b string) bool {
	if b == "" {
		return false
	}
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(fa, fb)
}

// prepare sets the silo's variables in the bundle's config, when it's a silo's.
func (s *Shim) prepare(inv Invocation) error {
	bundle := inv.Bundle
	if bundle == "" {
		bundle = "."
	}
	name := inv.Config
	if name == "" {
		name = "config.json"
	}
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(bundle, name)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("the bundle's config: %w", err)
	}
	config, err := io.ReadAll(io.LimitReader(f, maxConfig+1))
	st, serr := f.Stat()
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("the bundle's config: %w", err)
	}
	if serr != nil {
		return serr
	}
	if len(config) > maxConfig {
		return fmt.Errorf("the bundle's config %s is over %d MiB", path, maxConfig>>20)
	}
	ann, err := annotations(config)
	if err != nil {
		return err
	}
	short, ok := ann[Annotation]
	if !ok {
		return nil // not a silo with env secrets: untouched
	}
	if !shortID.MatchString(short) {
		return fmt.Errorf("annotation %s: %q isn't a silo's short id", Annotation, short)
	}
	envPath := filepath.Join(s.SecretsDir, short, "env")
	text, err := s.envFile(short)
	if err != nil {
		return fmt.Errorf("container %s: its silo's environment variables (%s) can't be read, so it isn't started: %w", inv.ID, envPath, err)
	}
	defer clear(text)
	vars, err := ParseEnvFile(text)
	if err != nil {
		return fmt.Errorf("container %s: %s: %w", inv.ID, envPath, err)
	}
	out, err := SetEnv(config, vars)
	if err != nil {
		return fmt.Errorf("container %s: %w", inv.ID, err)
	}
	defer clear(out)
	mem, fstype, err := s.InMemory(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("container %s: the bundle's filesystem: %w", inv.ID, err)
	}
	if !mem {
		return fmt.Errorf("container %s: its bundle %s is on a %s filesystem, not in memory: its environment variables would be written to disk there, so it isn't started", inv.ID, filepath.Dir(path), fstype)
	}
	return writeOver(path, out, st.Mode().Perm())
}

// envFile reads a silo's env file: SecretsDir and the silo's folder must be folders (not links)
// root owns and only root writes, the file a regular file of root's with one link, readable by
// root only, opened without following a link.
func (s *Shim) envFile(short string) ([]byte, error) {
	for _, d := range []string{s.SecretsDir, filepath.Join(s.SecretsDir, short)} {
		fi, err := os.Lstat(d)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("%s isn't a folder", d)
		}
		if err := s.owned(d, fi, 0o022); err != nil {
			return nil, err
		}
	}
	return s.readStrict(filepath.Join(s.SecretsDir, short, "env"), 0o077, 1<<20)
}

// readStrict reads a regular file of Owner's, not through a link, with no mode bit of deny set.
func (s *Shim) readStrict(path string, deny fs.FileMode, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a link", path)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s isn't a regular file", path)
	}
	if err := s.owned(path, fi, deny); err != nil {
		return nil, err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		return nil, fmt.Errorf("%s has %d links", path, st.Nlink)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		clear(b)
		return nil, fmt.Errorf("%s is too large", path)
	}
	return b, nil
}

func (s *Shim) owned(path string, fi fs.FileInfo, deny fs.FileMode) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: no owner", path)
	}
	if int(st.Uid) != s.Owner {
		return fmt.Errorf("%s is owned by uid %d, not %d", path, st.Uid, s.Owner)
	}
	if fi.Mode().Perm()&deny != 0 {
		return fmt.Errorf("%s has mode %04o", path, fi.Mode().Perm())
	}
	return nil
}

// writeOver replaces path with b atomically (a file beside it renamed over it), with mode.
func writeOver(path string, b []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config.json.kevaso-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}
