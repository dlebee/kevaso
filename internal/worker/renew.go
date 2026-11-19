package worker

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/pki"
)

// KeepCertificate renews this host's certificate once it is past two thirds of its life (or inside
// the last ten days), and presents the new one on the next handshake. A worker with no host
// certificate (a system node's own worker) waits. A failure is retried, from 10s doubling to 5min.
func KeepCertificate(ctx context.Context, c *client.Client, dataDir string, log func(string, ...any)) {
	if log == nil {
		log = func(string, ...any) {}
	}
	backoff := 10 * time.Second
	for {
		renewed, err := RenewHostCertificate(ctx, c, dataDir, time.Now())
		wait := time.Hour
		if err != nil {
			log("certificate renewal: %v (retrying)", err)
			wait = backoff
			if backoff < 5*time.Minute {
				backoff *= 2
			}
		} else {
			backoff = 10 * time.Second
			if renewed {
				log("certificate renewed")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// RenewHostCertificate renews the certificate in dataDir/pki when it is due at now. It writes the
// key and then the certificate (each through a temporary name), and the client presents the new
// pair. A renewed certificate for a different identity is not stored. renewed is false when it
// isn't due, or when there is no host certificate.
func RenewHostCertificate(ctx context.Context, c *client.Client, dataDir string, now time.Time) (bool, error) {
	dir := filepath.Join(dataDir, "pki")
	certPath, keyPath := filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	nb, na, ok := pki.CertificateLifetime(certPEM)
	if ok && client.RenewDue(nb, na, now) { // renew at two thirds of the lifetime
		cred, err := c.Renew(ctx)
		if err != nil {
			return false, err
		}
		oldID, err := pki.IdentityOfPEM(certPEM)
		if err != nil {
			return false, err
		}
		newID, err := pki.IdentityOfPEM(cred.Certificate)
		if err != nil {
			return false, err
		}
		if newID != oldID { // a renewed host certificate is the same host
			return false, fmt.Errorf("renewed certificate is for %s %s, not %s %s", newID.Type, newID.Name, oldID.Type, oldID.Name)
		}
		if err := commitRenewedPair(keyPath, certPath, cred.Key, cred.Certificate); err != nil {
			return false, err
		}
		if err := c.RotateCertificate(cred.Certificate, cred.Key); err != nil { // the live client presents the new certificate
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// commitRenewedPair installs a renewed key and certificate. The previous key is kept as
// path.prev until the certificate is renamed, so a crash between the two leaves a key that
// still matches the certificate on disk.
func commitRenewedPair(keyPath, certPath string, key, cert []byte) error {
	if err := stageRenewedKey(keyPath, key); err != nil {
		return err
	}
	return finishRenewedCert(keyPath, certPath, cert)
}

// stageRenewedKey puts key in place and keeps the previous key as .prev. A .prev already
// there is the key from before this renewal and is not replaced.
func stageRenewedKey(keyPath string, key []byte) error {
	next := keyPath + ".next"
	if err := writeFileAtomic(next, key, 0o600); err != nil {
		return err
	}
	prev := keyPath + ".prev"
	if _, err := os.Stat(keyPath); err == nil {
		if _, err := os.Stat(prev); os.IsNotExist(err) {
			if err := os.Rename(keyPath, prev); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if err := os.Remove(keyPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(next, keyPath)
}

// finishRenewedCert writes the certificate, then drops the previous key. The previous key
// stays if this write fails.
func finishRenewedCert(keyPath, certPath string, cert []byte) error {
	if err := writeFileAtomic(certPath, cert, 0o644); err != nil {
		return err
	}
	if err := os.Remove(keyPath + ".prev"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// loadHostPair reads the host certificate and the key that matches it: the current key, or
// the previous key when a renewal stopped between the two renames. The matching previous key
// is put back as the current key.
func loadHostPair(certPath, keyPath string) (cert, key []byte, err error) {
	cert, err = os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	if key, err = os.ReadFile(keyPath); err == nil && keyMatches(cert, key) {
		return cert, key, nil
	}
	prev, perr := os.ReadFile(keyPath + ".prev")
	if perr == nil && keyMatches(cert, prev) {
		if err := writeFileAtomic(keyPath, prev, 0o600); err != nil {
			return nil, nil, err
		}
		return cert, prev, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("%s does not match %s", keyPath, certPath)
}

func keyMatches(cert, key []byte) bool {
	_, err := tls.X509KeyPair(cert, key)
	return err == nil
}
