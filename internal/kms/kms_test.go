package kms

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvelope(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := OpenLocal(filepath.Join(dir, "kms.json"))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("sk-test-value-0123456789")
	aad := []byte("web3/infura-key/uid1")
	s, err := Seal(ctx, l, secret, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(s.Ciphertext, secret) || bytes.Contains(s.WrappedDEK, secret) {
		t.Fatal("plaintext visible in the sealed value")
	}
	got, err := Open(ctx, l, s, aad)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open = %q, %v", got, err)
	}
	if _, err := Open(ctx, l, s, []byte("web3/other/uid2")); err == nil {
		t.Fatal("opened with another secret's AAD: values could be swapped in the store")
	}
	tampered := s
	tampered.Ciphertext = append([]byte(nil), s.Ciphertext...)
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 1
	if _, err := Open(ctx, l, tampered, aad); err == nil {
		t.Fatal("opened a tampered value")
	}

	// The key file is 0600, and a reopened KMS reads what the first sealed.
	fi, err := os.Stat(filepath.Join(dir, "kms.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, %v", fi.Mode().Perm(), err)
	}
	l2, err := OpenLocal(filepath.Join(dir, "kms.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(ctx, l2, s, aad); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("reopened: %q, %v", got, err)
	}
}

func TestRotateRewrapRetire(t *testing.T) {
	ctx := context.Background()
	l, err := OpenLocal(filepath.Join(t.TempDir(), "kms.json"))
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("ns/a/u")
	s, err := Seal(ctx, l, []byte("v1"), aad)
	if err != nil {
		t.Fatal(err)
	}
	old := s.KeyID
	if _, err := l.Rotate(); err != nil {
		t.Fatal(err)
	}
	if got, err := Open(ctx, l, s, aad); err != nil || string(got) != "v1" {
		t.Fatalf("old key no longer decrypts before re-wrap: %v", err)
	}
	r, changed, err := Rewrap(ctx, l, s)
	if err != nil || !changed || r.KeyID == old {
		t.Fatalf("rewrap: %+v %v %v", r, changed, err)
	}
	if !bytes.Equal(r.Ciphertext, s.Ciphertext) {
		t.Fatal("rewrap re-encrypted the value: it should only re-wrap the data key")
	}
	if _, again, _ := Rewrap(ctx, l, r); again {
		t.Fatal("rewrap of a current value changed it")
	}
	if err := l.Retire(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, l, s, aad); err == nil {
		t.Fatal("retired key still decrypts")
	}
	if got, err := Open(ctx, l, r, aad); err != nil || string(got) != "v1" {
		t.Fatalf("re-wrapped value after retire: %v", err)
	}
}

func TestRecoveryKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := OpenLocal(filepath.Join(dir, "kms.json"))
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("ns/a/u")
	s, err := Seal(ctx, l, []byte("restored"), aad)
	if err != nil {
		t.Fatal(err)
	}
	rk := NewRecoveryKey()
	printed := rk.String()
	if !strings.HasPrefix(printed, "KVR1-") {
		t.Fatalf("printed %q", printed)
	}
	parsed, err := ParseRecoveryKey(strings.ToLower(printed))
	if err != nil || !bytes.Equal(parsed, rk) {
		t.Fatalf("parse(%q): %v", printed, err)
	}
	if _, err := ParseRecoveryKey("KVR1-AAAA"); err == nil {
		t.Fatal("short key parsed")
	}
	pub, err := rk.Public()
	if err != nil {
		t.Fatal(err)
	}
	// After a rotation the control plane escrows the new key with only the public half.
	if _, err := l.Rotate(); err != nil {
		t.Fatal(err)
	}
	esc, err := l.EscrowKeys(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(esc.Keys) != 2 {
		t.Fatalf("escrow holds %d keys, want both", len(esc.Keys))
	}
	st, _ := l.Status(ctx)

	// The backup alone (store with the escrow, no key file) is useless without the recovery key.
	if _, err := Recover(filepath.Join(dir, "new.json"), esc, NewRecoveryKey(), st.KeyID); err == nil {
		t.Fatal("recovered with the wrong recovery key")
	}
	l2, err := Recover(filepath.Join(dir, "new.json"), esc, parsed, st.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(ctx, l2, s, aad); err != nil || string(got) != "restored" {
		t.Fatalf("after recovery: %q, %v", got, err)
	}
}

func TestOpenLocalRefusesLooseFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kms.json")
	if _, err := OpenLocal(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(p); err == nil {
		t.Fatal("opened a key file others can read")
	}
}

func TestSealToRecovery(t *testing.T) {
	rk := NewRecoveryKey()
	pub, _ := rk.Public()
	data := []byte("the cluster's state")
	blob, err := SealToRecovery(pub, data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, data) {
		t.Fatal("plaintext visible")
	}
	if got, err := OpenWithRecovery(rk, blob); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("open = %q, %v", got, err)
	}
	if _, err := OpenWithRecovery(NewRecoveryKey(), blob); err == nil {
		t.Fatal("another recovery key opened the backup")
	}
	blob[len(blob)-1] ^= 1
	if _, err := OpenWithRecovery(rk, blob); err == nil {
		t.Fatal("a changed backup opened")
	}
	if _, err := OpenWithRecovery(rk, []byte("junk")); err == nil {
		t.Fatal("junk opened")
	}
}
