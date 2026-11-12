// Package backup makes and restores a control plane's backups.
//
// A backup is the cluster's state: the store (every object, the secrets' sealed values, the
// recovery escrow), the cluster CA and the audit log, in one file sealed to the recovery key's
// public half. The control plane can make one without the recovery key; only the recovery key
// opens it. The master key file is not in it: a restore rebuilds it from the escrow in the store,
// with the recovery key. So a stolen backup opens nothing, and a restore proves the recovery key
// works.
//
// Not in a backup: what runs in silos (their disks and volumes). Back those up from inside, or
// with your volumes' own snapshots.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
)

// Manifest says what a backup is of.
type Manifest struct {
	Format   int       `json:"format"`
	Cluster  string    `json:"cluster"`
	Host     string    `json:"host"` // the control-plane host it was taken on
	Created  time.Time `json:"created"`
	KMSKeyID string    `json:"kmsKeyID"` // the master key in use then
}

const (
	format       = 1
	manifestName = "manifest.json"
	storeName    = "store.db"
	auditName    = "audit.log"
	pkiDir       = "pki"
	maxFile      = 1 << 30
)

// Make backs up the control plane whose data directory is dataDir. snapshot writes a consistent
// copy of the live store to a path; recoveryPublic is the recovery key's public half.
func Make(ctx context.Context, dataDir string, snapshot func(ctx context.Context, path string) error, m Manifest, recoveryPublic []byte) ([]byte, error) {
	if len(recoveryPublic) == 0 {
		return nil, errors.New("no recovery key yet (kvoadm init makes it): a backup would have no key")
	}
	tmp, err := os.MkdirTemp(dataDir, ".backup-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	snap := filepath.Join(tmp, storeName)
	if err := snapshot(ctx, snap); err != nil {
		return nil, fmt.Errorf("store snapshot: %w", err)
	}
	m.Format, m.Created = format, m.Created.UTC()
	mb, _ := json.MarshalIndent(m, "", "  ")

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: m.Created}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := add(manifestName, mb); err != nil {
		return nil, err
	}
	files := []string{snap, filepath.Join(dataDir, auditName)}
	names := []string{storeName, auditName}
	if es, err := os.ReadDir(filepath.Join(dataDir, pkiDir)); err == nil {
		for _, e := range es {
			if e.Type().IsRegular() {
				files = append(files, filepath.Join(dataDir, pkiDir, e.Name()))
				names = append(names, pkiDir+"/"+e.Name())
			}
		}
	} else {
		return nil, fmt.Errorf("cluster CA: %w", err)
	}
	for i, f := range files {
		b, err := os.ReadFile(f)
		if errors.Is(err, os.ErrNotExist) && names[i] == auditName {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := add(names[i], b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return kms.SealToRecovery(recoveryPublic, buf.Bytes())
}

// Open opens a backup with the recovery key: its manifest and files.
func Open(blob []byte, rk kms.RecoveryKey) (Manifest, map[string][]byte, error) {
	var m Manifest
	plain, err := kms.OpenWithRecovery(rk, blob)
	if err != nil {
		return m, nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return m, nil, err
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, nil, err
		}
		if !allowed(h.Name) || h.Typeflag != tar.TypeReg || h.Size > maxFile {
			return m, nil, fmt.Errorf("unexpected entry %q in the backup", h.Name)
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFile))
		if err != nil {
			return m, nil, err
		}
		files[h.Name] = b
	}
	if err := json.Unmarshal(files[manifestName], &m); err != nil || m.Format != format {
		return m, nil, fmt.Errorf("backup manifest: format %d, %v", m.Format, err)
	}
	if files[storeName] == nil {
		return m, nil, errors.New("the backup has no store")
	}
	return m, files, nil
}

func allowed(name string) bool {
	switch name {
	case manifestName, storeName, auditName:
		return true
	}
	rest, ok := strings.CutPrefix(name, pkiDir+"/")
	return ok && rest != "" && !strings.ContainsAny(rest, `/\`) && rest != "." && rest != ".."
}

// Restore puts a backup into dataDir, which must hold no control plane yet, and rebuilds the master
// key from the escrow with the recovery key. Run it before starting the control plane there.
func Restore(ctx context.Context, blob []byte, rk kms.RecoveryKey, dataDir string) (Manifest, error) {
	m, files, err := Open(blob, rk)
	if err != nil {
		return m, err
	}
	for _, p := range []string{storeName, filepath.Join("kms", "local.json"), filepath.Join(pkiDir, "ca.key")} {
		if _, err := os.Stat(filepath.Join(dataDir, p)); err == nil {
			return m, fmt.Errorf("%s already holds a control plane (%s): restore onto a fresh machine", dataDir, p)
		}
	}
	if err := os.MkdirAll(filepath.Join(dataDir, pkiDir), 0o700); err != nil {
		return m, err
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return m, err
	}
	for name, b := range files {
		if name == manifestName {
			continue
		}
		if err := os.WriteFile(filepath.Join(dataDir, filepath.FromSlash(name)), b, 0o600); err != nil {
			return m, err
		}
	}
	st, err := store.OpenSQLite(filepath.Join(dataDir, storeName), 0)
	if err != nil {
		return m, err
	}
	defer func() { _ = st.Close() }()
	esc, err := secrets.LoadEscrow(ctx, st)
	if err != nil {
		return m, fmt.Errorf("the backup's recovery escrow: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "kms"), 0o700); err != nil {
		return m, err
	}
	if _, err := kms.Recover(filepath.Join(dataDir, "kms", "local.json"), esc, rk, m.KMSKeyID); err != nil {
		return m, fmt.Errorf("master key: %w", err)
	}
	return m, nil
}
