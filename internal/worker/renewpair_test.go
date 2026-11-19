package worker

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/internal/pki"
)

// A renewal that stops after the new key is in place, and is then tried again, still loads the
// key that matches the certificate on disk.
func TestAnInterruptedRenewalKeepsTheMatchingKey(t *testing.T) {
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := pki.Identity{Type: "host", Name: "hv1", Role: "worker"}
	certA, keyA := clientPair(t, ca, id, time.Now(), time.Hour)
	_, keyB := clientPair(t, ca, id, time.Now(), time.Hour)
	certC, keyC := clientPair(t, ca, id, time.Now(), time.Hour)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key")
	if err := os.WriteFile(certPath, certA, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyA, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stageRenewedKey(keyPath, keyB); err != nil {
		t.Fatal(err)
	}
	if err := stageRenewedKey(keyPath, keyC); err != nil {
		t.Fatal(err)
	}
	gotCert, gotKey, err := loadHostPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCert, certA) || !bytes.Equal(gotKey, keyA) {
		t.Fatal("loaded a key that does not match the certificate")
	}

	dir = t.TempDir()
	certPath, keyPath = filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key")
	if err := os.WriteFile(certPath, certA, 0o644); err != nil || os.WriteFile(keyPath, keyA, 0o600) != nil {
		t.Fatal(err)
	}
	if err := stageRenewedKey(keyPath, keyC); err != nil {
		t.Fatal(err)
	}
	if err := finishRenewedCert(keyPath, certPath, certC); err != nil {
		t.Fatal(err)
	}
	gotCert, gotKey, err = loadHostPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCert, certC) || !bytes.Equal(gotKey, keyC) {
		t.Fatal("a finished renewal did not keep the new pair")
	}
	if _, err := os.Stat(keyPath + ".prev"); !os.IsNotExist(err) {
		t.Fatalf("previous key still present: %v", err)
	}
}
