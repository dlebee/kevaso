package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"kevaso.com/core/internal/store"
)

// Internal store kinds; the API never serves them.
const (
	KindKey     = "OIDCSigningKey"
	KindUser    = "OIDCUser"
	KindInvite  = "OIDCInvite"
	KindSession = "OIDCSession"
)

// User is someone who can sign in.
type User struct {
	Name     string    `json:"name"`
	Groups   []string  `json:"groups,omitempty"`
	Disabled bool      `json:"disabled,omitempty"`
	Created  time.Time `json:"created"`
}

type invite struct {
	SecretHash string    `json:"secretHash"`
	User       string    `json:"user"`
	Expires    time.Time `json:"expires"`
	UsedAt     time.Time `json:"usedAt,omitempty"`
}

// session is one signed-in client: its refresh token rotates on every use.
type session struct {
	User        string    `json:"user"`
	RefreshHash string    `json:"refreshHash"`
	PrevHash    string    `json:"prevHash,omitempty"` // presenting this again means the token was stolen
	Expires     time.Time `json:"expires"`            // slides forward on every refresh
	Created     time.Time `json:"created"`
	RotatedAt   time.Time `json:"rotatedAt,omitempty"`
}

type signingKey struct {
	KID string `json:"kid"`
	PEM string `json:"pem"` // PKCS#8 EC private key
}

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func sameHash(secret, want string) bool {
	return subtle.ConstantTimeCompare([]byte(hash(secret)), []byte(want)) == 1
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// split reads PREFIX<id>.<secret>.
func split(tok, prefix string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(tok, prefix)
	if !found {
		return "", "", false
	}
	id, secret, ok = strings.Cut(rest, ".")
	return id, secret, ok && id != "" && secret != ""
}

func getJSON(ctx context.Context, st store.Store, key store.Key, v any) (int64, error) {
	o, err := st.Get(ctx, key)
	if err != nil {
		return 0, err
	}
	return o.Revision, json.Unmarshal(o.Data, v)
}

// loadKey returns the cluster's token-signing key, creating it on first use.
func loadKey(ctx context.Context, st store.Store) (*ecdsa.PrivateKey, string, error) {
	key := store.Key{Kind: KindKey, Name: "current"}
	for attempt := 0; attempt < 3; attempt++ {
		var k signingKey
		if _, err := getJSON(ctx, st, key, &k); err == nil {
			blk, _ := pem.Decode([]byte(k.PEM))
			if blk == nil {
				return nil, "", errors.New("signing key: bad PEM")
			}
			pk, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, "", err
			}
			ec, ok := pk.(*ecdsa.PrivateKey)
			if !ok {
				return nil, "", errors.New("signing key isn't ECDSA")
			}
			return ec, k.KID, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, "", err
		}
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", err
		}
		der, err := x509.MarshalPKCS8PrivateKey(pk)
		if err != nil {
			return nil, "", err
		}
		data, _ := json.Marshal(signingKey{KID: random(8), PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
		if _, err := st.Create(ctx, key, data); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, "", err
		}
		// Created (or another control plane won the race): read it back.
	}
	return nil, "", errors.New("signing key: couldn't load or create")
}
