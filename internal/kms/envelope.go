package kms

import (
	"context"
	"errors"
)

// Sealed is one secret value at rest: the value encrypted with its own data key, and the data key
// wrapped by the KMS. AAD binds it to the secret it belongs to (namespace/name/uid), so sealed values
// can't be swapped between secrets in the store.
type Sealed struct {
	KeyID      string `json:"keyID"`
	WrappedDEK []byte `json:"wrappedDEK"`
	Ciphertext []byte `json:"ciphertext"`
}

// Seal encrypts plaintext under a fresh data key.
func Seal(ctx context.Context, k KMS, plaintext, aad []byte) (Sealed, error) {
	dek := randomKey()
	ct, err := seal(dek, plaintext, aad)
	if err != nil {
		return Sealed{}, err
	}
	wrapped, keyID, err := k.Encrypt(ctx, dek)
	if err != nil {
		return Sealed{}, err
	}
	clear(dek)
	return Sealed{KeyID: keyID, WrappedDEK: wrapped, Ciphertext: ct}, nil
}

// Open decrypts a sealed value.
func Open(ctx context.Context, k KMS, s Sealed, aad []byte) ([]byte, error) {
	dek, err := k.Decrypt(ctx, s.WrappedDEK, s.KeyID)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	pt, err := open(dek, s.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("kms: sealed value doesn't open (wrong secret, or tampered with)")
	}
	return pt, nil
}

// Rewrap wraps the data key again with the KMS's current key; the ciphertext doesn't change.
func Rewrap(ctx context.Context, k KMS, s Sealed) (Sealed, bool, error) {
	st, err := k.Status(ctx)
	if err != nil {
		return s, false, err
	}
	if s.KeyID == st.KeyID {
		return s, false, nil
	}
	dek, err := k.Decrypt(ctx, s.WrappedDEK, s.KeyID)
	if err != nil {
		return s, false, err
	}
	defer clear(dek)
	wrapped, keyID, err := k.Encrypt(ctx, dek)
	if err != nil {
		return s, false, err
	}
	s.WrappedDEK, s.KeyID = wrapped, keyID
	return s, true, nil
}
