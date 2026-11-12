package secrets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/store"
)

func newVault(t *testing.T) (*Vault, *kms.Local) {
	t.Helper()
	l, err := kms.OpenLocal(filepath.Join(t.TempDir(), "kms.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &Vault{Store: store.NewMemory(100), KMS: l, Now: time.Now}, l
}

func secret(name, uid, typ string) *v1.Secret {
	return &v1.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "web3", Name: name, UID: uid}, Spec: v1.SecretSpec{Type: typ}}
}

func TestPutValueVersions(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t)
	s := secret("infura", "u1", "")
	if v.Has(ctx, s) {
		t.Fatal("has a value before Put")
	}
	st, err := v.Put(ctx, s, []byte("key-1"))
	if err != nil || st.Version != 1 || st.Size != 5 {
		t.Fatalf("put: %+v %v", st, err)
	}
	st, _ = v.Put(ctx, s, []byte("key-2"))
	if st.Version != 2 {
		t.Fatalf("rotation: version %d", st.Version)
	}
	got, ver, err := v.Value(ctx, s)
	if err != nil || string(got) != "key-2" || ver != 2 {
		t.Fatalf("value = %q v%d %v", got, ver, err)
	}
	// Nothing in the store holds the plain value.
	objs, _, _ := v.Store.List(ctx, store.Selector{Kind: KindValue})
	for _, o := range objs {
		if bytes.Contains(o.Data, []byte("key-2")) {
			t.Fatal("plain value in the store")
		}
	}
	// A new secret with the same name (another uid) doesn't get the old value.
	again := secret("infura", "u2", "")
	if _, _, err := v.Value(ctx, again); !errors.Is(err, ErrNoValue) {
		t.Fatalf("re-created secret read the old value: %v", err)
	}
	if st, _ := v.Put(ctx, again, []byte("fresh")); st.Version != 1 {
		t.Fatalf("re-created secret starts at version %d", st.Version)
	}
	v.Forget(ctx, "web3", "infura")
	if v.Has(ctx, again) {
		t.Fatal("value kept after Forget")
	}
}

func TestSignKeysNeverReadable(t *testing.T) {
	s := secret("validator", "u1", v1.SecretEd25519)
	if s.Readable() || s.Allows(v1.DeliverBroker) || !s.Allows(v1.DeliverSign) {
		t.Fatal("a signing key must only allow sign and never be readable")
	}
	yes := true
	o := secret("token", "u1", "")
	o.Spec.ValueReadable = &yes
	if !o.Readable() || o.Allows(v1.DeliverSign) {
		t.Fatal("opaque secrets: readable by default, never sign")
	}
	o.Spec.AllowedDelivery = []string{v1.DeliverInject}
	if o.Allows(v1.DeliverFile) || !o.Allows(v1.DeliverInject) {
		t.Fatal("allowedDelivery not applied")
	}
}

func TestSign(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t)
	for _, typ := range []string{v1.SecretEd25519, v1.SecretECDSAP256} {
		s := secret("k-"+typ, "u1", typ)
		key, err := Generate(typ)
		if err != nil {
			t.Fatal(err)
		}
		st, err := v.Put(ctx, s, key)
		if err != nil || st.PublicKey == "" {
			t.Fatalf("%s: put %+v %v", typ, st, err)
		}
		msg := []byte("transfer 10 to alice")
		sig, err := v.Sign(ctx, s, SignRequest{Payload: msg})
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := hex.DecodeString(st.PublicKey)
		switch typ {
		case v1.SecretEd25519:
			if !ed25519.Verify(pub, msg, sig) || ed25519.Verify(pub, append(msg, '!'), sig) {
				t.Fatal("ed25519 signature doesn't verify (or verifies a changed message)")
			}
		case v1.SecretECDSAP256:
			pk, err := x509.ParsePKIXPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(msg)
			if !ecdsa.VerifyASN1(pk.(*ecdsa.PublicKey), h[:], sig) {
				t.Fatal("ecdsa signature doesn't verify")
			}
		}
	}
	if _, err := v.Sign(ctx, secret("x", "u", ""), SignRequest{Payload: []byte("a")}); err == nil {
		t.Fatal("signed with an opaque secret")
	}
	if _, err := PublicKey(v1.SecretEd25519, []byte("short")); err == nil {
		t.Fatal("accepted a 5-byte ed25519 key")
	}
}

func TestSlashingProtection(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t)
	s := secret("validator-1-key", "u1", v1.SecretEd25519)
	key, _ := Generate(v1.SecretEd25519)
	if _, err := v.Put(ctx, s, key); err != nil {
		t.Fatal(err)
	}
	slot := func(n int64) *int64 { return &n }
	for _, tc := range []struct {
		slot    *int64
		payload string
		ok      bool
		why     string
	}{
		{nil, "a", false, "protection needs a slot"},
		{slot(10), "block-10-a", true, "first signature"},
		{slot(10), "block-10-a", true, "the same payload again is fine"},
		{slot(10), "block-10-b", false, "a second payload for slot 10 equivocates"},
		{slot(9), "block-9", false, "going back a slot"},
		{slot(11), "block-11", true, "the next slot"},
	} {
		_, err := v.Sign(ctx, s, SignRequest{Payload: []byte(tc.payload), Slot: tc.slot, Protection: true})
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.why, err)
		}
		if err != nil && !errors.Is(err, ErrSlashing) {
			t.Errorf("%s: not a slashing refusal: %v", tc.why, err)
		}
	}
	// Without protection the same key signs anything.
	if _, err := v.Sign(ctx, s, SignRequest{Payload: []byte("block-9")}); err != nil {
		t.Fatal(err)
	}
}

func TestRewrapAll(t *testing.T) {
	ctx := context.Background()
	v, l := newVault(t)
	a, b := secret("a", "u1", ""), secret("b", "u2", "")
	_, _ = v.Put(ctx, a, []byte("va"))
	_, _ = v.Put(ctx, b, []byte("vb"))
	if _, err := l.Rotate(); err != nil {
		t.Fatal(err)
	}
	n, err := v.RewrapAll(ctx)
	if err != nil || n != 2 {
		t.Fatalf("rewrap: %d %v", n, err)
	}
	if err := l.Retire(); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*v1.Secret{a, b} {
		got, ver, err := v.Value(ctx, s)
		if err != nil || !strings.HasPrefix(string(got), "v") || ver != 1 {
			t.Fatalf("%s after rotation: %q v%d %v", s.Name, got, ver, err)
		}
	}
	if n, _ := v.RewrapAll(ctx); n != 0 {
		t.Fatalf("second rewrap changed %d", n)
	}
}
