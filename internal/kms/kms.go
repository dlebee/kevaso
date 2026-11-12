// Package kms is the master key behind secrets (design §8.4a): envelope encryption, where each
// secret has its own data key and only data keys are wrapped by the master key. Switching KMS or
// rotating the master key re-wraps data keys and never re-encrypts the secrets.
//
// The interface mirrors Kubernetes' KMS v2 (Status, Encrypt, Decrypt), so plugins for clouds,
// Vault / OpenBao or a TPM fit behind it. Local is the built-in plugin: a root-only key file on the
// control-plane host, plus a recovery key printed once, which wraps the master keys in the store so
// a backup (store + recovery key) can be restored and a stolen backup alone is useless.
package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// KMS wraps and unwraps data keys.
type KMS interface {
	// Status reports whether the KMS works and which key Encrypt uses now.
	Status(ctx context.Context) (Status, error)
	// Encrypt wraps a data key with the current master key.
	Encrypt(ctx context.Context, plaintext []byte) (ciphertext []byte, keyID string, err error)
	// Decrypt unwraps a data key wrapped by keyID.
	Decrypt(ctx context.Context, ciphertext []byte, keyID string) ([]byte, error)
}

// Status is the KMS's health.
type Status struct {
	Healthy bool
	KeyID   string
}

// ErrUnknownKey: the ciphertext was wrapped by a key this KMS doesn't have.
var ErrUnknownKey = errors.New("kms: unknown key")

// seal and open are AES-256-GCM with a random nonce in front.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plaintext, aad), nil
}

func open(key, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < g.NonceSize() {
		return nil, errors.New("kms: ciphertext too short")
	}
	return g.Open(nil, ciphertext[:g.NonceSize()], ciphertext[g.NonceSize():], aad)
}

func randomKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

// ── the local plugin ─────────────────────────────────────────────────────────

// Local keeps master keys in a root-only file. The newest key encrypts; older ones only decrypt,
// until every data key is re-wrapped and they're retired.
type Local struct {
	path string
	mu   sync.RWMutex
	file localFile
}

type localFile struct {
	Current string            `json:"current"`
	Keys    map[string][]byte `json:"keys"` // by id
}

// OpenLocal reads the key file at path, creating it (and a first master key) if it's missing.
func OpenLocal(path string) (*Local, error) {
	l := &Local{path: path}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		l.file = localFile{Keys: map[string][]byte{}}
		if _, err := l.Rotate(); err != nil {
			return nil, err
		}
		return l, nil
	case err != nil:
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("kms: %s is readable by others (mode %o): it must be 0600", path, fi.Mode().Perm())
	}
	if err := json.Unmarshal(b, &l.file); err != nil {
		return nil, fmt.Errorf("kms: %s: %w", path, err)
	}
	if l.file.Keys[l.file.Current] == nil {
		return nil, fmt.Errorf("kms: %s has no current key", path)
	}
	return l, nil
}

func (l *Local) save() error {
	b, err := json.Marshal(l.file)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// Rotate makes a new master key the current one and returns its id. Old keys stay until Retire.
func (l *Local) Rotate() (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	id := "local-" + time.Now().UTC().Format("20060102T150405") + "-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomKey()[:5]))
	l.file.Keys[id] = randomKey()
	l.file.Current = id
	return id, l.save()
}

// Retire drops every key but the current one (after every data key was re-wrapped with it).
func (l *Local) Retire() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id := range l.file.Keys {
		if id != l.file.Current {
			delete(l.file.Keys, id)
		}
	}
	return l.save()
}

// KeyIDs lists the keys the file holds, current last.
func (l *Local) KeyIDs() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []string
	for id := range l.file.Keys {
		if id != l.file.Current {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return append(out, l.file.Current)
}

// Status implements KMS.
func (l *Local) Status(context.Context) (Status, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return Status{Healthy: l.file.Keys[l.file.Current] != nil, KeyID: l.file.Current}, nil
}

// Encrypt implements KMS.
func (l *Local) Encrypt(_ context.Context, plaintext []byte) ([]byte, string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	ct, err := seal(l.file.Keys[l.file.Current], plaintext, []byte(l.file.Current))
	return ct, l.file.Current, err
}

// Decrypt implements KMS.
func (l *Local) Decrypt(_ context.Context, ciphertext []byte, keyID string) ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	k := l.file.Keys[keyID]
	if k == nil {
		return nil, fmt.Errorf("%w %q", ErrUnknownKey, keyID)
	}
	return open(k, ciphertext, []byte(keyID))
}

// ── the recovery key ─────────────────────────────────────────────────────────

// RecoveryKey is printed once by kvoadm init, to keep offline. It's 32 random bytes, shown as
// KVR1- and base32 in groups of four.
type RecoveryKey []byte

// NewRecoveryKey makes one.
func NewRecoveryKey() RecoveryKey { return randomKey() }

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func (k RecoveryKey) String() string {
	s := b32.EncodeToString(k)
	var groups []string
	for len(s) > 4 {
		groups, s = append(groups, s[:4]), s[4:]
	}
	return "KVR1-" + strings.Join(append(groups, s), "-")
}

// ParseRecoveryKey reads what String printed (spaces, dashes and case don't matter).
func ParseRecoveryKey(s string) (RecoveryKey, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	rest, ok := strings.CutPrefix(s, "KVR1-")
	if !ok {
		return nil, errors.New("recovery key: want KVR1-…")
	}
	rest = strings.NewReplacer("-", "", " ", "").Replace(rest)
	k, err := b32.DecodeString(rest)
	if err != nil || len(k) != 32 {
		return nil, errors.New("recovery key: not a Kevaso recovery key (check for typos)")
	}
	return k, nil
}

// Escrow is the master keys wrapped for the recovery key: kept in the store, so a backup carries
// it. Each key is sealed to the recovery key's public half (X25519 + AES-GCM), so the control plane
// can escrow a new master key after a rotation without ever holding the recovery key.
type Escrow struct {
	RecoveryPublic []byte            `json:"recoveryPublic"`
	Keys           map[string][]byte `json:"keys"` // key id → ephemeral public key ‖ sealed master key
}

// Public is the recovery key's public half.
func (k RecoveryKey) Public() ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return priv.PublicKey().Bytes(), nil
}

func escrowKEK(shared, ephPub, recPub []byte, id string) []byte {
	h := sha256.New()
	for _, b := range [][]byte{[]byte("kevaso-escrow-v1"), shared, ephPub, recPub, []byte(id)} {
		h.Write(b)
	}
	return h.Sum(nil)
}

// EscrowKeys seals every master key of l to the recovery public key.
func (l *Local) EscrowKeys(recoveryPublic []byte) (Escrow, error) {
	pub, err := ecdh.X25519().NewPublicKey(recoveryPublic)
	if err != nil {
		return Escrow{}, err
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	e := Escrow{RecoveryPublic: recoveryPublic, Keys: map[string][]byte{}}
	for id, k := range l.file.Keys {
		eph, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return Escrow{}, err
		}
		shared, err := eph.ECDH(pub)
		if err != nil {
			return Escrow{}, err
		}
		ct, err := seal(escrowKEK(shared, eph.PublicKey().Bytes(), recoveryPublic, id), k, []byte(id))
		if err != nil {
			return Escrow{}, err
		}
		e.Keys[id] = append(eph.PublicKey().Bytes(), ct...)
	}
	return e, nil
}

// Recover rebuilds a key file at path from an escrow and the recovery key (restoring a backup on a
// new control plane). current is the key new data keys should use.
func Recover(path string, e Escrow, rk RecoveryKey, current string) (*Local, error) {
	priv, err := ecdh.X25519().NewPrivateKey(rk)
	if err != nil {
		return nil, err
	}
	f := localFile{Keys: map[string][]byte{}, Current: current}
	for id, blob := range e.Keys {
		if len(blob) < 32 {
			return nil, errors.New("kms: escrow entry too short")
		}
		eph, err := ecdh.X25519().NewPublicKey(blob[:32])
		if err != nil {
			return nil, err
		}
		shared, err := priv.ECDH(eph)
		if err != nil {
			return nil, err
		}
		k, err := open(escrowKEK(shared, blob[:32], priv.PublicKey().Bytes(), id), blob[32:], []byte(id))
		if err != nil {
			return nil, errors.New("recovery key doesn't open this backup's keys")
		}
		f.Keys[id] = k
	}
	if f.Keys[current] == nil {
		return nil, fmt.Errorf("kms: the escrow has no key %q", current)
	}
	l := &Local{path: path, file: f}
	return l, l.save()
}
