package kms

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// Backups are sealed to the recovery key's public half: the control plane can make one without
// holding the recovery key, and only the recovery key opens it.

var backupMagic = []byte("KVB1")

// SealToRecovery seals data so that only the recovery key whose public half is given opens it.
func SealToRecovery(recoveryPublic, data []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(recoveryPublic)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	ct, err := seal(backupKEK(shared, ephPub, recoveryPublic), data, backupMagic)
	if err != nil {
		return nil, err
	}
	return append(append(append([]byte{}, backupMagic...), ephPub...), ct...), nil
}

// OpenWithRecovery opens what SealToRecovery sealed.
func OpenWithRecovery(rk RecoveryKey, blob []byte) ([]byte, error) {
	if !bytes.HasPrefix(blob, backupMagic) || len(blob) < len(backupMagic)+32 {
		return nil, errors.New("not a Kevaso backup")
	}
	priv, err := ecdh.X25519().NewPrivateKey(rk)
	if err != nil {
		return nil, err
	}
	ephPub := blob[len(backupMagic) : len(backupMagic)+32]
	eph, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	data, err := open(backupKEK(shared, ephPub, priv.PublicKey().Bytes()), blob[len(backupMagic)+32:], backupMagic)
	if err != nil {
		return nil, errors.New("this recovery key doesn't open this backup (or the file was changed)")
	}
	return data, nil
}

func backupKEK(shared, ephPub, recPub []byte) []byte {
	h := sha256.New()
	for _, b := range [][]byte{[]byte("kevaso-backup-v1"), shared, ephPub, recPub} {
		h.Write(b)
	}
	return h.Sum(nil)
}
