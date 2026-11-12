package backup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
)

// A control plane's data directory with one secret, backed up, restored elsewhere: the secret
// opens there with the rebuilt master key, after a rotation too.
func TestBackupAndRestore(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	ca, _ := pki.NewCA("c", time.Now())
	if err := ca.Save(filepath.Join(src, "pki")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "audit.log"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(src, "store.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	k, err := kms.OpenLocal(filepath.Join(src, "kms", "local.json"))
	if err != nil {
		t.Fatal(err)
	}
	vault := &secrets.Vault{Store: st, KMS: k, Now: time.Now}
	sec := &v1.Secret{ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "payments", UID: "u1"}}
	if _, err := vault.Put(ctx, sec, []byte("hunter2-hunter2")); err != nil {
		t.Fatal(err)
	}
	// What kvoadm init does: the recovery key, escrowed. Then a rotation re-escrows.
	rk := kms.NewRecoveryKey()
	pub, _ := rk.Public()
	escrow := func() {
		esc, err := k.EscrowKeys(pub)
		if err == nil {
			err = secrets.SaveEscrow(ctx, st, esc)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	escrow()
	if _, err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.RewrapAll(ctx); err != nil {
		t.Fatal(err)
	}
	escrow()
	if err := k.Retire(); err != nil {
		t.Fatal(err)
	}
	escrow()
	status, _ := k.Status(ctx)

	blob, err := Make(ctx, src, st.Snapshot, Manifest{Cluster: "prod", Host: "cp-1", Created: time.Now(), KMSKeyID: status.KeyID}, pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range [][]byte{[]byte("hunter2"), []byte("PRIVATE KEY")} {
		if bytes.Contains(blob, leak) {
			t.Fatalf("%q readable in the backup", leak)
		}
	}
	if _, _, err := Open(blob, kms.NewRecoveryKey()); err == nil {
		t.Fatal("another recovery key opened the backup")
	}
	m, files, err := Open(blob, rk)
	if err != nil || m.Cluster != "prod" || m.Host != "cp-1" {
		t.Fatalf("open: %+v %v", m, err)
	}
	if _, ok := files["kms/local.json"]; ok {
		t.Fatal("the master key file is in the backup")
	}

	dst := filepath.Join(t.TempDir(), "kevaso")
	if _, err := Restore(ctx, blob, rk, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.LoadCA(filepath.Join(dst, "pki")); err != nil {
		t.Fatalf("CA not restored: %v", err)
	}
	st2, err := store.OpenSQLite(filepath.Join(dst, "store.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	k2, err := kms.OpenLocal(filepath.Join(dst, "kms", "local.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := (&secrets.Vault{Store: st2, KMS: k2, Now: time.Now}).Value(ctx, sec)
	if err != nil || string(got) != "hunter2-hunter2" {
		t.Fatalf("secret after restore: %q %v", got, err)
	}
	if s2, _ := k2.Status(ctx); s2.KeyID != status.KeyID {
		t.Errorf("current key %s, want %s", s2.KeyID, status.KeyID)
	}
	if fi, _ := os.Stat(filepath.Join(dst, "kms", "local.json")); fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v", fi.Mode().Perm())
	}
	if _, err := Restore(ctx, blob, rk, dst); err == nil {
		t.Fatal("restored over an existing control plane")
	}
}

func TestAllowed(t *testing.T) {
	for name, ok := range map[string]bool{"store.db": true, "pki/ca.key": true, "../etc/passwd": false, "pki/../x": false, "pki/": false, "kms/local.json": false, "/etc/x": false} {
		if allowed(name) != ok {
			t.Errorf("%q: %v", name, !ok)
		}
	}
}
