package worker

import (
	"context"
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
		if err := writeFileAtomic(keyPath, cred.Key, 0o600); err != nil {
			return false, err
		}
		if err := writeFileAtomic(certPath, cred.Certificate, 0o644); err != nil {
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
