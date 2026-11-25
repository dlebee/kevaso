// Package secrets keeps secret values sealed in the store (envelope encryption through the KMS)
// and does what needs the value on the control plane: deliver it to a silo's host, or sign with
// it so the key never leaves (design §8).
//
// Values live in an internal kind (SecretValue), next to the Secret object the API serves, which
// never holds a value. A secret's keys are sealed together, as one envelope: the plaintext is
// EncodeData's (hack/design/secret-keys.md). A value is bound to its Secret's uid: deleting and re-creating a secret with
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
	"sort"
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

// ErrWriteOnly: the value was written while the secret was write-only; a person can't have it.
var ErrWriteOnly = errors.New("secret value was written while the secret was write-only")

type record struct {
	UID     string     `json:"uid"`
	Version int64      `json:"version"`
	Sealed  kms.Sealed `json:"sealed"`
	// WriteOnly: the value was written while the secret was write-only. No person is ever given
	// it, whatever the secret's setting is later (K-060): it stays in the vault for silos' use
	// until a write brings a value written readable.
	WriteOnly bool `json:"writeOnly,omitempty"`
}

// Vault reads and writes sealed values.
type Vault struct {
	Store store.Store
	KMS   kms.KMS
	Now   func() time.Time
}

func aad(ns, name, uid, registry string) []byte {
	b := ns + "/" + name + "/" + uid
	if registry != "" { // the sealed value opens only for this registry
		b += "/" + registry
	}
	return []byte(b)
}

// registryOf is the registry a secret's value is bound to ("" for anything but a registry secret).
func registryOf(sec *v1.Secret) string {
	if sec != nil && sec.Spec.Type == v1.SecretRegistry {
		return v1.RegistryBinding(sec.Spec.Server)
	}
	return ""
}

func valueKey(ns, name string) store.Key {
	return store.Key{Kind: KindValue, Namespace: ns, Name: name}
}

// EncodeData is the plaintext a secret's keys are sealed as: JSON, keys sorted. Pure.
func EncodeData(data map[string][]byte) []byte {
	b, _ := json.Marshal(data) // map[string][]byte always marshals; keys come out sorted
	return b
}

// DecodeData reads EncodeData's plaintext.
func DecodeData(b []byte) (map[string][]byte, error) {
	var m map[string][]byte
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, errors.New("the sealed value isn't a set of keys")
	}
	return m, nil
}

// Clear zeroes every value in data.
func Clear(data map[string][]byte) {
	for _, b := range data {
		clear(b)
	}
}

// Keys are data's key names, sorted, and their bytes together. Pure.
func Keys(data map[string][]byte) ([]string, int) {
	keys := make([]string, 0, len(data))
	n := 0
	for k, b := range data {
		keys = append(keys, k)
		n += len(b)
	}
	sort.Strings(keys)
	return keys, n
}

// Put seals data (every key) as the secret's new version and returns the status to record. sec is
// the secret as it is (or is about to be) stored: if it is write-only, so is the value, for good;
// sticky keeps it write-only also when sec is readable now (a write that changes some keys of a
// value written write-only, K-060).
func (v *Vault) Put(ctx context.Context, sec *v1.Secret, data map[string][]byte, sticky bool) (v1.SecretStatus, error) {
	pub, err := PublicKey(sec.Spec.Type, data[v1.ValueKey])
	if err != nil {
		return v1.SecretStatus{}, err
	}
	pt := EncodeData(data)
	defer clear(pt)
	r, err := v.putRecord(ctx, sec.Namespace, sec.Name, sec.UID, registryOf(sec), pt, sticky || !sec.Readable())
	if err != nil {
		return v1.SecretStatus{}, err
	}
	now := v.Now().UTC().Truncate(time.Second)
	keys, size := Keys(data)
	return v1.SecretStatus{Version: r.Version, UpdatedAt: &now, Keys: keys, Size: size, PublicKey: pub}, nil
}

// WrittenWriteOnly reports whether the secret's current value was written while it was write-only.
func (v *Vault) WrittenWriteOnly(ctx context.Context, sec *v1.Secret) bool {
	r, _, err := v.read(ctx, sec)
	return err == nil && r.WriteOnly
}

// PutCluster seals data as the cluster secret's new version. The value is readable again (a
// cluster-admin's --reveal, or a ClusterRole pinned to the name): it is not write-only in the vault.
// The version is what the caller records; the clock that stamps changedAt is the server's.
func (v *Vault) PutCluster(ctx context.Context, cs *v1.ClusterSecret, data map[string][]byte) (int64, error) {
	pt := EncodeData(data)
	defer clear(pt)
	r, err := v.putRecord(ctx, "", cs.Name, cs.UID, "", pt, false)
	if err != nil {
		return 0, err
	}
	return r.Version, nil
}

// putRecord seals value under namespace/name, bound to uid. A new uid starts at version 1; the
// same uid bumps the version. writeOnly sticks to the value (K-060).
func (v *Vault) putRecord(ctx context.Context, ns, name, uid, registry string, value []byte, writeOnly bool) (record, error) {
	sealed, err := kms.Seal(ctx, v.KMS, value, aad(ns, name, uid, registry))
	if err != nil {
		return record{}, err
	}
	k := valueKey(ns, name)
	for attempt := 0; attempt < 5; attempt++ {
		r := record{UID: uid, Version: 1, Sealed: sealed, WriteOnly: writeOnly}
		cur, err := v.Store.Get(ctx, k)
		var werr error
		switch {
		case errors.Is(err, store.ErrNotFound):
			b, _ := json.Marshal(r)
			_, werr = v.Store.Create(ctx, k, b)
		case err != nil:
			return record{}, err
		default:
			var old record
			if json.Unmarshal(cur.Data, &old) == nil && old.UID == uid {
				r.Version = old.Version + 1
			}
			b, _ := json.Marshal(r)
			_, werr = v.Store.Update(ctx, k, b, cur.Revision)
		}
		if errors.Is(werr, store.ErrConflict) || errors.Is(werr, store.ErrExists) {
			continue
		}
		if werr != nil {
			return record{}, werr
		}
		return r, nil
	}
	return record{}, errors.New("secret value keeps changing; try again")
}

// Has reports whether the secret has a value.
func (v *Vault) Has(ctx context.Context, sec *v1.Secret) bool {
	_, _, err := v.read(ctx, sec)
	return err == nil
}

func (v *Vault) read(ctx context.Context, sec *v1.Secret) (record, int64, error) {
	return v.readAt(ctx, sec.Namespace, sec.Name, sec.UID)
}

func (v *Vault) readAt(ctx context.Context, ns, name, uid string) (record, int64, error) {
	o, err := v.Store.Get(ctx, valueKey(ns, name))
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
	if r.UID != uid {
		return record{}, 0, ErrNoValue
	}
	return r, o.Revision, nil
}

// open opens a record's keys.
func (v *Vault) open(ctx context.Context, r record, ad []byte) (map[string][]byte, error) {
	pt, err := kms.Open(ctx, v.KMS, r.Sealed, ad)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	return DecodeData(pt)
}

// ClusterValue opens a cluster secret's current keys. Callers decide who may have them.
func (v *Vault) ClusterValue(ctx context.Context, cs *v1.ClusterSecret) (map[string][]byte, int64, error) {
	r, _, err := v.readAt(ctx, "", cs.Name, cs.UID)
	if err != nil {
		return nil, 0, err
	}
	d, err := v.open(ctx, r, aad("", cs.Name, cs.UID, ""))
	return d, r.Version, err
}

// Value opens the secret's current keys. Callers decide who may have them; the vault doesn't.
func (v *Vault) Value(ctx context.Context, sec *v1.Secret) (map[string][]byte, int64, error) {
	r, _, err := v.read(ctx, sec)
	if err != nil {
		return nil, 0, err
	}
	d, err := v.open(ctx, r, aad(sec.Namespace, sec.Name, sec.UID, registryOf(sec)))
	return d, r.Version, err
}

// KeyValue opens one key of the secret (ErrNoValue when it has no such key).
func (v *Vault) KeyValue(ctx context.Context, sec *v1.Secret, key string) ([]byte, int64, error) {
	d, ver, err := v.Value(ctx, sec)
	if err != nil {
		return nil, 0, err
	}
	b, ok := d[key]
	delete(d, key)
	Clear(d)
	if !ok {
		return nil, 0, ErrNoValue
	}
	return b, ver, nil
}

// PersonValue is Value for a person reading it back: refused (ErrWriteOnly) for a value that was
// written while the secret was write-only, even if the secret has become readable since.
func (v *Vault) PersonValue(ctx context.Context, sec *v1.Secret) (map[string][]byte, int64, error) {
	r, _, err := v.read(ctx, sec)
	if err != nil {
		return nil, 0, err
	}
	if r.WriteOnly {
		return nil, 0, ErrWriteOnly
	}
	d, err := v.open(ctx, r, aad(sec.Namespace, sec.Name, sec.UID, registryOf(sec)))
	return d, r.Version, err
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
	if typ == "" || typ == v1.SecretOpaque || typ == v1.SecretRegistry {
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
	value, _, err := v.KeyValue(ctx, sec, v1.ValueKey)
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
