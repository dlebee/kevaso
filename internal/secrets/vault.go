// Package secrets keeps secret values sealed in the store (envelope encryption through the KMS)
// and does what needs the value on the control plane: deliver it to a silo's host, or sign with
// it so the key never leaves (design §8).
//
// Values live in an internal kind (SecretValue), next to the Secret object the API serves, which
// never holds a value. A value is bound to its Secret's uid: deleting and re-creating a secret with
// the same name never brings back the old value.
package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/store"
)

// Internal store kinds; the API never serves them.
const (
	KindValue  = "SecretValue"
	KindSigned = "SignState"
	KindEscrow = "KMSEscrow"
)

// ErrNoValue: the secret has no value yet (or it belongs to an older secret of the same name).
var ErrNoValue = errors.New("secret has no value")

type record struct {
	UID     string     `json:"uid"`
	Version int64      `json:"version"`
	Sealed  kms.Sealed `json:"sealed"`
}

// Vault reads and writes sealed values.
type Vault struct {
	Store store.Store
	KMS   kms.KMS
	Now   func() time.Time
}

func aad(ns, name, uid string) []byte { return []byte(ns + "/" + name + "/" + uid) }

func valueKey(ns, name string) store.Key {
	return store.Key{Kind: KindValue, Namespace: ns, Name: name}
}

// Put seals value as the secret's new version and returns the status to record.
func (v *Vault) Put(ctx context.Context, sec *v1.Secret, value []byte) (v1.SecretStatus, error) {
	pub, err := PublicKey(sec.Spec.Type, value)
	if err != nil {
		return v1.SecretStatus{}, err
	}
	sealed, err := kms.Seal(ctx, v.KMS, value, aad(sec.Namespace, sec.Name, sec.UID))
	if err != nil {
		return v1.SecretStatus{}, err
	}
	k := valueKey(sec.Namespace, sec.Name)
	for attempt := 0; attempt < 5; attempt++ {
		r := record{UID: sec.UID, Version: 1, Sealed: sealed}
		cur, err := v.Store.Get(ctx, k)
		var werr error
		switch {
		case errors.Is(err, store.ErrNotFound):
			b, _ := json.Marshal(r)
			_, werr = v.Store.Create(ctx, k, b)
		case err != nil:
			return v1.SecretStatus{}, err
		default:
			var old record
			if json.Unmarshal(cur.Data, &old) == nil && old.UID == sec.UID {
				r.Version = old.Version + 1
			}
			b, _ := json.Marshal(r)
			_, werr = v.Store.Update(ctx, k, b, cur.Revision)
		}
		if errors.Is(werr, store.ErrConflict) || errors.Is(werr, store.ErrExists) {
			continue
		}
		if werr != nil {
			return v1.SecretStatus{}, werr
		}
		now := v.Now().UTC().Truncate(time.Second)
		return v1.SecretStatus{Version: r.Version, UpdatedAt: &now, Size: len(value), PublicKey: pub}, nil
	}
	return v1.SecretStatus{}, errors.New("secret value keeps changing; try again")
}

// Has reports whether the secret has a value.
func (v *Vault) Has(ctx context.Context, sec *v1.Secret) bool {
	_, _, err := v.read(ctx, sec)
	return err == nil
}

func (v *Vault) read(ctx context.Context, sec *v1.Secret) (record, int64, error) {
	o, err := v.Store.Get(ctx, valueKey(sec.Namespace, sec.Name))
	if errors.Is(err, store.ErrNotFound) {
		return record{}, 0, ErrNoValue
	}
	if err != nil {
		return record{}, 0, err
	}
	var r record
	if err := json.Unmarshal(o.Data, &r); err != nil {
		return record{}, 0, err
	}
	if r.UID != sec.UID {
		return record{}, 0, ErrNoValue
	}
	return r, o.Revision, nil
}

// Value opens the secret's current value. Callers decide who may have it; the vault doesn't.
func (v *Vault) Value(ctx context.Context, sec *v1.Secret) ([]byte, int64, error) {
	r, _, err := v.read(ctx, sec)
	if err != nil {
		return nil, 0, err
	}
	pt, err := kms.Open(ctx, v.KMS, r.Sealed, aad(sec.Namespace, sec.Name, sec.UID))
	return pt, r.Version, err
}

// Forget removes a deleted secret's value and signing state.
func (v *Vault) Forget(ctx context.Context, ns, name string) {
	for _, k := range []store.Key{valueKey(ns, name), {Kind: KindSigned, Namespace: ns, Name: name}} {
		if o, err := v.Store.Get(ctx, k); err == nil {
			_, _ = v.Store.Delete(ctx, k, o.Revision)
		}
	}
}

// RewrapAll re-wraps every value's data key with the KMS's current key (after a master key
// rotation); the values themselves aren't re-encrypted. It returns how many changed.
func (v *Vault) RewrapAll(ctx context.Context) (int, error) {
	objs, _, err := v.Store.List(ctx, store.Selector{Kind: KindValue})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, o := range objs {
		var r record
		if err := json.Unmarshal(o.Data, &r); err != nil {
			return n, err
		}
		s, changed, err := kms.Rewrap(ctx, v.KMS, r.Sealed)
		if err != nil {
			return n, fmt.Errorf("%s: %w", o.Key, err)
		}
		if !changed {
			continue
		}
		r.Sealed = s
		b, _ := json.Marshal(r)
		if _, err := v.Store.Update(ctx, o.Key, b, o.Revision); err != nil {
			return n, fmt.Errorf("%s: %w", o.Key, err)
		}
		n++
	}
	return n, nil
}

// ── values the server makes, and signing keys ────────────────────────────────

// Generate makes a value for a secret of type typ: 32 random bytes (hex) for opaque secrets, a new
// private key for signing keys.
func Generate(typ string) ([]byte, error) {
	switch typ {
	case "", v1.SecretOpaque:
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		return []byte(hex.EncodeToString(b)), nil
	case v1.SecretEd25519:
		_, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return sk.Seed(), nil
	case v1.SecretECDSAP256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return x509.MarshalPKCS8PrivateKey(k)
	}
	return nil, fmt.Errorf("unknown secret type %q", typ)
}

// signer reads a signing key: ed25519 is its 32-byte seed; ECDSA P-256 is PKCS#8, DER or PEM.
func signer(typ string, value []byte) (any, error) {
	switch typ {
	case v1.SecretEd25519:
		if len(value) != ed25519.SeedSize {
			return nil, fmt.Errorf("an ed25519 key is its %d-byte seed, got %d bytes", ed25519.SeedSize, len(value))
		}
		return ed25519.NewKeyFromSeed(value), nil
	case v1.SecretECDSAP256:
		der := value
		if blk, _ := pem.Decode(value); blk != nil {
			der = blk.Bytes
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("an ecdsa-p256 key is PKCS#8 (DER or PEM): %w", err)
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok || ek.Curve != elliptic.P256() {
			return nil, errors.New("not an ECDSA P-256 key")
		}
		return ek, nil
	}
	return nil, fmt.Errorf("a %q secret isn't a signing key", typ)
}

// PublicKey is the public half of a signing key, hex: the raw 32 bytes for ed25519, PKIX DER for
// ECDSA. Opaque secrets have none ("").
func PublicKey(typ string, value []byte) (string, error) {
	if typ == "" || typ == v1.SecretOpaque {
		return "", nil
	}
	k, err := signer(typ, value)
	if err != nil {
		return "", err
	}
	switch k := k.(type) {
	case ed25519.PrivateKey:
		return hex.EncodeToString(k.Public().(ed25519.PublicKey)), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		return hex.EncodeToString(der), err
	}
	return "", nil
}

// ErrSlashing: a different payload for a slot already signed (or an older slot).
var ErrSlashing = errors.New("refused by slashing protection")

type signState struct {
	UID  string `json:"uid"`
	Slot int64  `json:"slot"`
	Hash string `json:"hash"` // sha256 of the payload signed for Slot
}

// SignRequest is one signature to make.
type SignRequest struct {
	Payload []byte
	// Slot, with protection on, must never go back, and one slot gets one payload only (signing
	// the same payload again is fine).
	Slot       *int64
	Protection bool
}

// Sign signs with the secret's key, which never leaves the control plane. ed25519 signs the payload;
// ECDSA signs its SHA-256 (ASN.1 DER).
func (v *Vault) Sign(ctx context.Context, sec *v1.Secret, req SignRequest) ([]byte, error) {
	if !sec.KeyType() {
		return nil, fmt.Errorf("%s/%s isn't a signing key", sec.Namespace, sec.Name)
	}
	value, _, err := v.Value(ctx, sec)
	if err != nil {
		return nil, err
	}
	defer clear(value)
	k, err := signer(sec.Spec.Type, value)
	if err != nil {
		return nil, err
	}
	if req.Protection {
		if req.Slot == nil {
			return nil, fmt.Errorf("%w: this key needs a slot with every payload", ErrSlashing)
		}
		if err := v.protect(ctx, sec, *req.Slot, req.Payload); err != nil {
			return nil, err
		}
	}
	switch k := k.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(k, req.Payload), nil
	case *ecdsa.PrivateKey:
		h := sha256.Sum256(req.Payload)
		return ecdsa.SignASN1(rand.Reader, k, h[:])
	}
	return nil, errors.New("unsupported key")
}

// protect records the slot before signing (so two concurrent requests can't both pass).
func (v *Vault) protect(ctx context.Context, sec *v1.Secret, slot int64, payload []byte) error {
	sum := sha256.Sum256(payload)
	h := hex.EncodeToString(sum[:])
	k := store.Key{Kind: KindSigned, Namespace: sec.Namespace, Name: sec.Name}
	for attempt := 0; attempt < 10; attempt++ {
		next, _ := json.Marshal(signState{UID: sec.UID, Slot: slot, Hash: h})
		cur, err := v.Store.Get(ctx, k)
		if errors.Is(err, store.ErrNotFound) {
			if _, err := v.Store.Create(ctx, k, next); errors.Is(err, store.ErrExists) {
				continue
			} else {
				return err
			}
		}
		if err != nil {
			return err
		}
		var st signState
		if err := json.Unmarshal(cur.Data, &st); err != nil {
			return err
		}
		if st.UID == sec.UID {
			switch {
			case slot < st.Slot:
				return fmt.Errorf("%w: slot %d is before the last signed slot %d", ErrSlashing, slot, st.Slot)
			case slot == st.Slot && h != st.Hash:
				return fmt.Errorf("%w: slot %d was already signed with a different payload", ErrSlashing, slot)
			case slot == st.Slot:
				return nil
			}
		}
		if _, err := v.Store.Update(ctx, k, next, cur.Revision); errors.Is(err, store.ErrConflict) {
			continue
		} else {
			return err
		}
	}
	return errors.New("signing state keeps changing; try again")
}

// ── the recovery escrow ──────────────────────────────────────────────────────

// SaveEscrow keeps the master keys wrapped by the recovery key in the store (one record).
func SaveEscrow(ctx context.Context, s store.Store, e kms.Escrow) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	k := store.Key{Kind: KindEscrow, Name: "local"}
	cur, err := s.Get(ctx, k)
	if errors.Is(err, store.ErrNotFound) {
		_, err = s.Create(ctx, k, b)
		return err
	}
	if err != nil {
		return err
	}
	_, err = s.Update(ctx, k, b, cur.Revision)
	return err
}

// HasEscrow reports whether a recovery key was already made.
func HasEscrow(ctx context.Context, s store.Store) bool {
	_, err := s.Get(ctx, store.Key{Kind: KindEscrow, Name: "local"})
	return err == nil
}

// EscrowPublic is the recovery key's public half from the stored escrow (nil if none).
func EscrowPublic(ctx context.Context, s store.Store) []byte {
	o, err := s.Get(ctx, store.Key{Kind: KindEscrow, Name: "local"})
	if err != nil {
		return nil
	}
	var e kms.Escrow
	if json.Unmarshal(o.Data, &e) != nil {
		return nil
	}
	return e.RecoveryPublic
}

// LoadEscrow reads the recovery escrow from the store.
func LoadEscrow(ctx context.Context, s store.Store) (kms.Escrow, error) {
	var e kms.Escrow
	o, err := s.Get(ctx, store.Key{Kind: KindEscrow, Name: "local"})
	if err != nil {
		return e, err
	}
	return e, json.Unmarshal(o.Data, &e)
}
