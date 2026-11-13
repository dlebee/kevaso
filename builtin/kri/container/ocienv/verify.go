package ocienv

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Check is VerifyDocker's setup.
type Check struct {
	Image string // an image with sh and cat, present or pullable (default busybox:1.36)
	// Dirs are the engine's folders on disk that must not hold the value: by default docker's
	// container folder for the container, and containerd's metadata database.
	Dirs []string
	// Docker runs the docker CLI (default: exec of "docker").
	Docker func(ctx context.Context, args ...string) ([]byte, error)
}

// VerifyDocker proves, on a Linux host whose Docker has this runtime registered (the container
// runtime's install), that a variable given through it reaches the container's process and
// nowhere the engine keeps: it makes a silo-like env file in SecretsDir (as root), starts a
// container through the runtime with the annotation, and checks the variable is in its PID 1's
// environment, not in `docker inspect`, and not in any file under the engine's container folder
// (/var/lib/docker/containers/ID) or containerd's metadata. The value is random and never printed.
// Everything it made is removed. The bare-metal suite calls this as it is.
func VerifyDocker(ctx context.Context, c Check) error {
	if c.Image == "" {
		c.Image = "busybox:1.36"
	}
	if c.Docker == nil {
		c.Docker = func(ctx context.Context, args ...string) ([]byte, error) {
			var out bytes.Buffer
			cmd := exec.CommandContext(ctx, "docker", args...)
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			return bytes.TrimSpace(out.Bytes()), err
		}
	}
	b := make([]byte, 21)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	short := hex.EncodeToString(b[:5])
	value := "kv-check-" + hex.EncodeToString(b[5:])
	const name = "KEVASO_ENV_CHECK"
	dir := filepath.Join(SecretsDir, short)
	if err := os.MkdirAll(SecretsDir, 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.WriteFile(filepath.Join(dir, "env"), []byte(name+"="+value+"\n"), 0o600); err != nil {
		return err
	}
	cname := "kevaso-env-check-" + short
	defer func() { _, _ = c.Docker(context.WithoutCancel(ctx), "rm", "-f", cname) }()
	if out, err := c.Docker(ctx, "run", "-d", "--name", cname, "--runtime", RuntimeName,
		"--annotation", Annotation+"="+short, "-e", name+"=from-the-engine", c.Image, "sleep", "300"); err != nil {
		return fmt.Errorf("docker run through %s: %v: %s", RuntimeName, err, out)
	}
	environ, err := c.Docker(ctx, "exec", cname, "cat", "/proc/1/environ")
	if err != nil {
		return fmt.Errorf("reading the container's environment: %v", err)
	}
	found := false
	for _, kv := range bytes.Split(environ, []byte{0}) {
		if string(kv) == name+"="+value {
			found = true
		}
		if string(kv) == name+"=from-the-engine" {
			return errors.New("the engine's value of the variable is in the process: the secret didn't win")
		}
	}
	clear(environ)
	if !found {
		return fmt.Errorf("%s isn't in the container's PID 1 environment: the runtime didn't set it", name)
	}
	id, err := c.Docker(ctx, "inspect", "--format", "{{.Id}}", cname)
	if err != nil {
		return fmt.Errorf("docker inspect: %v", err)
	}
	inspect, err := c.Docker(ctx, "inspect", cname)
	if err != nil {
		return fmt.Errorf("docker inspect: %v", err)
	}
	if bytes.Contains(inspect, []byte(value)) {
		return errors.New("docker inspect shows the variable's value")
	}
	dirs := c.Dirs
	if dirs == nil {
		dirs = []string{"/var/lib/docker/containers/" + strings.TrimSpace(string(id)), "/var/lib/containerd/io.containerd.metadata.v1.bolt"}
	}
	for _, d := range dirs {
		err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) && p == d {
					return filepath.SkipDir
				}
				return err
			}
			if !e.Type().IsRegular() {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if bytes.Contains(data, []byte(value)) {
				return fmt.Errorf("the variable's value is on disk in %s", p)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
