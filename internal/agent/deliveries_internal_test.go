package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// shSilo is a fake runtime whose exec runs the command with the real sh, in a folder standing in
// for the silo's root, with a mount table of its own.
type shSilo struct {
	*fake.Runtime
	root, mounts string
	execs        [][]string
	stdins       [][]byte
}

func newShSilo(t *testing.T, runFS string) (*shSilo, kri.ID) {
	t.Helper()
	root := t.TempDir()
	mounts := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(mounts, []byte("/dev/vda1 / ext4 rw 0 0\nnone /run "+runFS+" rw 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &shSilo{Runtime: fake.New(), root: root, mounts: mounts}
	s.Program = func(ctx context.Context, _ kri.ID, req kri.ExecRequest) int {
		var in []byte
		if req.Stdin != nil {
			in, _ = io.ReadAll(req.Stdin)
		}
		s.execs = append(s.execs, req.Command)
		s.stdins = append(s.stdins, in)
		cmd := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...)
		cmd.Env = append(os.Environ(), "KEVASO_TEST_ROOT="+root, "KEVASO_TEST_MOUNTS="+mounts, "PATH=/usr/bin:/bin")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(in), req.Stdout, req.Stderr
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			return 127
		}
		return 0
	}
	id := kri.ID{Namespace: "web3", Name: "node", UID: "u1"}
	ctx := context.Background()
	if err := s.Create(ctx, kri.Spec{ID: id}); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx, id); err != nil {
		t.Fatal(err)
	}
	return s, id
}

func (s *shSilo) read(t *testing.T, p string) (string, os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.root, p))
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	fi, _ := os.Stat(filepath.Join(s.root, p))
	return string(b), fi.Mode().Perm()
}

func (s *shSilo) gone(p string) bool {
	_, err := os.Stat(filepath.Join(s.root, p))
	return os.IsNotExist(err)
}

// values answers delivery-values with ds.
func values(ds ...client.Delivery) func(string) (client.BrokerResponse, error) {
	return func(op string) (client.BrokerResponse, error) {
		if op != client.OpDeliveryValues {
			return client.BrokerResponse{}, errors.New("unexpected op " + op)
		}
		out := make([]client.Delivery, len(ds))
		for i, d := range ds {
			d.Value = append([]byte(nil), d.Value...)
			out[i] = d
		}
		return client.BrokerResponse{Deliveries: out}, nil
	}
}

func TestHostWrittenDeliveries(t *testing.T) {
	ctx := context.Background()
	s, id := newShSilo(t, "tmpfs")
	a := &Agent{}
	tls := client.Delivery{Name: "tls-key", Mode: v1.DeliverFile, Path: "/run/secrets/tls.pem", Version: 1, Value: []byte("-----BEGIN KEY-----")}
	legacy := client.Delivery{Name: "legacy-token", Mode: v1.DeliverEnv, Env: "LEGACY_TOKEN", Version: 1, Value: []byte("tok'en")}
	note, err := a.writeDeliveries(ctx, s, id, []client.Delivery{tls, legacy}, values(tls, legacy), "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "1 files, 1 environment variables") {
		t.Errorf("note %q", note)
	}
	if v, mode := s.read(t, "/run/secrets/tls.pem"); v != "-----BEGIN KEY-----" || mode != 0o400 {
		t.Fatalf("file delivery: %q %v", v, mode)
	}
	if v, mode := s.read(t, EnvFile); v != "LEGACY_TOKEN='tok'\\''en'\n" || mode != 0o400 {
		t.Fatalf("env delivery: %q %v", v, mode)
	}
	if v, mode := s.read(t, EnvProfile); !strings.Contains(v, ". "+EnvFile) || mode != 0o644 || strings.Contains(v, "tok") {
		t.Fatalf("profile: %q %v", v, mode)
	}
	// Values only ever went on stdin, never in argv.
	for _, c := range s.execs {
		if strings.Contains(strings.Join(c, " "), "BEGIN KEY") || strings.Contains(strings.Join(c, " "), "tok'en") {
			t.Fatalf("a secret in argv: %q", c)
		}
	}

	// Rotation rewrites; a delivery that's gone is removed (and the profile with the last env var).
	tls.Version, tls.Value = 2, []byte("-----BEGIN KEY v2-----")
	if _, err := a.writeDeliveries(ctx, s, id, []client.Delivery{tls}, values(tls), ""); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.read(t, "/run/secrets/tls.pem"); v != "-----BEGIN KEY v2-----" {
		t.Fatalf("after rotation: %q", v)
	}
	if !s.gone(EnvFile) || !s.gone(EnvProfile) {
		t.Fatal("env file or profile kept after the env delivery went")
	}
	if v, _ := s.read(t, DeliveredFile); v != "/run/secrets/tls.pem\n" {
		t.Fatalf("delivered list: %q", v)
	}
	// The grant goes: nothing is left.
	if _, err := a.writeDeliveries(ctx, s, id, nil, values(), ""); err != nil {
		t.Fatal(err)
	}
	if !s.gone("/run/secrets/tls.pem") {
		t.Fatal("file kept after its grant went")
	}
	// Not under /run: refused before anything runs.
	bad := client.Delivery{Name: "x", Mode: v1.DeliverFile, Path: "/etc/x", Version: 1, Value: []byte("v")}
	if _, err := a.writeDeliveries(ctx, s, id, []client.Delivery{bad}, values(bad), ""); err == nil || !strings.Contains(err.Error(), "under /run") || !s.gone("/etc/x") {
		t.Fatalf("outside /run: %v", err)
	}
	// A list a hostile silo edited never makes the host remove anything outside /run.
	keep := filepath.Join(s.root, "etc/keep")
	_ = os.MkdirAll(filepath.Dir(keep), 0o755)
	_ = os.WriteFile(keep, []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(s.root, DeliveredFile), []byte("/etc/keep\n"), 0o600)
	if _, err := a.writeDeliveries(ctx, s, id, nil, values(), ""); err != nil || s.gone("/etc/keep") {
		t.Fatalf("removed outside /run: %v", err)
	}
}

// A secret is never written onto a disk: /run that isn't tmpfs is refused, and the reason says so.
func TestDeliveriesOnlyOnTmpfs(t *testing.T) {
	s, id := newShSilo(t, "ext4")
	tls := client.Delivery{Name: "tls-key", Mode: v1.DeliverFile, Path: "/run/secrets/tls.pem", Version: 1, Value: []byte("k")}
	_, err := (&Agent{}).writeDeliveries(context.Background(), s, id, []client.Delivery{tls}, values(tls), "")
	if err == nil || !strings.Contains(err.Error(), "not tmpfs") {
		t.Fatalf("on ext4: %v", err)
	}
	if !s.gone("/run/secrets/tls.pem") && !s.gone("/run/secrets/tls.pem.kvo-tmp") {
		t.Fatal("written onto a disk")
	}
}

// The egress CA in a VM: with no trust-store tooling, a bundle of its own and the environment
// variables; once per CA.
func TestEgressCAInVM(t *testing.T) {
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		t.Skip("this machine has update-ca-certificates: the env-only path can't be tried here")
	}
	s, id := newShSilo(t, "tmpfs")
	a := &Agent{EgressCA: []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n")}
	_ = os.MkdirAll(filepath.Join(s.root, "etc/ssl/certs"), 0o755)
	_ = os.WriteFile(filepath.Join(s.root, "etc/ssl/certs/ca-certificates.crt"), []byte("SYSTEM CAS\n"), 0o644)
	_ = os.WriteFile(filepath.Join(s.root, "etc/environment"), []byte("PATH=/usr/bin\nSSL_CERT_FILE=/old\n"), 0o644)
	note, err := a.writeDeliveries(context.Background(), s, id, nil, values(), "hash1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "environment variables only") {
		t.Errorf("note %q", note)
	}
	if v, _ := s.read(t, "/etc/kevaso/ca-bundle.crt"); !strings.HasPrefix(v, "SYSTEM CAS\n") || !strings.Contains(v, "\nCA\n") {
		t.Fatalf("bundle: %q", v)
	}
	env, _ := s.read(t, "/etc/environment")
	if !strings.Contains(env, "PATH=/usr/bin\n") || strings.Contains(env, "/old") || !strings.Contains(env, "SSL_CERT_FILE=/etc/kevaso/ca-bundle.crt") ||
		!strings.Contains(env, "NODE_EXTRA_CA_CERTS=/etc/kevaso/egress-ca.crt") {
		t.Fatalf("environment: %q", env)
	}
	n := len(s.execs)
	if _, err := a.writeDeliveries(context.Background(), s, id, nil, values(), "hash1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.read(t, "/etc/environment"); got != env || len(s.execs) != n+2 {
		t.Fatalf("second pass changed things: %q (%d execs)", got, len(s.execs)-n)
	}
}

func TestDeliveriesKey(t *testing.T) {
	d := []client.Delivery{{Name: "a", Mode: "file", Path: "/run/secrets/a", Version: 1}}
	k := deliveriesKey(d, "")
	d2 := []client.Delivery{{Name: "a", Mode: "file", Path: "/run/secrets/a", Version: 2}}
	if k == deliveriesKey(d2, "") || k == deliveriesKey(d, "ca") || k == deliveriesKey(nil, "") || k != deliveriesKey(d, "") {
		t.Fatal("the key doesn't follow versions, paths or the CA")
	}
}
