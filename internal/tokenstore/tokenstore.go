// Package tokenstore keeps kvo's sign-in tokens out of the config file (design §9.2): in the macOS
// Keychain, or in a 0600 file under ~/.kevaso/tokens elsewhere (and when $KVO_TOKEN_STORE=file).
package tokenstore

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// ErrNotFound: nothing stored under that name.
var ErrNotFound = errors.New("no stored token")

// Store holds one secret per name (a kvo context).
type Store interface {
	Get(name string) ([]byte, error)
	Set(name string, secret []byte) error
	Delete(name string) error
}

// Default picks the store for this machine. dir is where file tokens go (~/.kevaso/tokens).
func Default(dir string) Store {
	switch os.Getenv("KVO_TOKEN_STORE") {
	case "file":
		return File{Dir: dir}
	case "keychain":
		return Keychain{}
	}
	if runtime.GOOS == "darwin" {
		return Keychain{}
	}
	return File{Dir: dir}
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9][-A-Za-z0-9._]*$`)

func check(name string) error {
	if !safeName.MatchString(name) {
		return fmt.Errorf("bad token name %q", name)
	}
	return nil
}

// File stores each secret in DIR/NAME (0600, directory 0700).
type File struct{ Dir string }

func (f File) Get(name string) ([]byte, error) {
	if err := check(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(f.Dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

func (f File) Set(name string, secret []byte) error {
	if err := check(name); err != nil {
		return err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(f.Dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, secret, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(f.Dir, name))
}

func (f File) Delete(name string) error {
	if err := check(name); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(f.Dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Keychain uses the macOS login keychain through /usr/bin/security. Secrets go to it on stdin
// (`security -i`), never on a command line where other processes could read them.
type Keychain struct {
	// Run runs security with args and stdin (tests replace it).
	Run func(args []string, stdin []byte) ([]byte, error)
}

const service = "com.kevaso.kvo"

func (k Keychain) run(args []string, stdin []byte) ([]byte, error) {
	if k.Run != nil {
		return k.Run(args, stdin)
	}
	cmd := exec.Command("/usr/bin/security", args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return out.Bytes(), fmt.Errorf("security %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func (k Keychain) Get(name string) ([]byte, error) {
	if err := check(name); err != nil {
		return nil, err
	}
	out, err := k.run([]string{"find-generic-password", "-s", service, "-a", name, "-w"}, nil)
	if err != nil {
		if strings.Contains(err.Error(), "could not be found") {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
}

// Set stores the secret base64-encoded, so nothing in it needs quoting in security's command
// language.
func (k Keychain) Set(name string, secret []byte) error {
	if err := check(name); err != nil {
		return err
	}
	line := fmt.Sprintf("add-generic-password -U -s %s -a %s -l %q -w %s\n", service, name, "kvo: "+name, base64.StdEncoding.EncodeToString(secret))
	_, err := k.run([]string{"-i"}, []byte(line))
	return err
}

func (k Keychain) Delete(name string) error {
	if err := check(name); err != nil {
		return err
	}
	_, err := k.run([]string{"delete-generic-password", "-s", service, "-a", name}, nil)
	if err != nil && strings.Contains(err.Error(), "could not be found") {
		return nil
	}
	return err
}
