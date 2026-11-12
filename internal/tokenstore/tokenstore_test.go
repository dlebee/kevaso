package tokenstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFile(t *testing.T) {
	f := File{Dir: filepath.Join(t.TempDir(), "tokens")}
	if _, err := f.Get("demo"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.Set("demo", []byte(`{"refresh":"kvr_x.y"}`)); err != nil {
		t.Fatal(err)
	}
	if b, err := f.Get("demo"); err != nil || string(b) != `{"refresh":"kvr_x.y"}` {
		t.Fatalf("%q %v", b, err)
	}
	fi, _ := os.Stat(filepath.Join(f.Dir, "demo"))
	di, _ := os.Stat(f.Dir)
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("modes %v %v", fi.Mode().Perm(), di.Mode().Perm())
	}
	if err := f.Delete("demo"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get("demo"); !errors.Is(err, ErrNotFound) {
		t.Fatal("still there after delete")
	}
	for _, bad := range []string{"../x", "a/b", "", ".hidden"} {
		if err := f.Set(bad, nil); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The secret reaches security on stdin only, never in its arguments.
func TestKeychainKeepsSecretsOffTheCommandLine(t *testing.T) {
	var calls [][]string
	var stdins []string
	stored := ""
	k := Keychain{Run: func(args []string, stdin []byte) ([]byte, error) {
		calls = append(calls, args)
		stdins = append(stdins, string(stdin))
		switch args[0] {
		case "-i":
			f := strings.Fields(string(stdin))
			stored = f[len(f)-1]
		case "find-generic-password":
			if stored == "" {
				return nil, errors.New("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.")
			}
			return []byte(stored + "\n"), nil
		}
		return nil, nil
	}}
	if _, err := k.Get("demo"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	secret := `{"refresh":"kvr_s3cret.value with "quotes" and spaces"}`
	if err := k.Set("demo", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if b, err := k.Get("demo"); err != nil || string(b) != secret {
		t.Fatalf("%q %v", b, err)
	}
	for _, a := range calls {
		if strings.Contains(strings.Join(a, " "), "s3cret") {
			t.Fatalf("secret on the command line: %v", a)
		}
	}
	for _, in := range stdins {
		if strings.Contains(in, "s3cret") {
			t.Fatal("secret written in the clear (want base64)")
		}
	}
}

// On a Mac, the real Keychain round-trips (set KVO_TEST_KEYCHAIN=1; it adds and removes an item).
func TestRealKeychain(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("KVO_TEST_KEYCHAIN") == "" {
		t.Skip("set KVO_TEST_KEYCHAIN=1 on a Mac")
	}
	k := Keychain{}
	name := "kvo-test-" + strings.ReplaceAll(t.Name(), "/", "-")
	defer func() { _ = k.Delete(name) }()
	if err := k.Set(name, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if b, err := k.Get(name); err != nil || string(b) != "hello" {
		t.Fatalf("%q %v", b, err)
	}
}
