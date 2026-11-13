package login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"kevaso.com/core/internal/tokenstore"
)

// Saved is what kvo keeps for a context, in the token store (never in the config file).
type Saved struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	Expiry       time.Time `json:"expiry"`
}

// Save stores tokens under name.
func Save(st tokenstore.Store, name string, t *oauth2.Token) error {
	b, err := json.Marshal(Saved{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, Expiry: t.Expiry})
	if err != nil {
		return err
	}
	return st.Set(name, b)
}

func load(st tokenstore.Store, name string) (Saved, error) {
	var s Saved
	b, err := st.Get(name)
	if errors.Is(err, tokenstore.ErrNotFound) {
		return s, errors.New("not signed in: run kvo login")
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

func fresh(s Saved) bool { return s.AccessToken != "" && time.Until(s.Expiry) > 30*time.Second }

// Tokens returns a function that gives a valid access token for the context, refreshing (and
// saving the rotated refresh token) when it's about to expire. Concurrent kvo commands take turns
// through a lock file, so they don't present the same refresh token twice.
func Tokens(server string, caPEM []byte, st tokenstore.Store, name, lockDir string) func(context.Context) (string, error) {
	f := AccessTokens(server, caPEM, st, name, lockDir)
	return func(ctx context.Context) (string, error) {
		t, _, err := f(ctx)
		return t, err
	}
}

// AccessTokens is Tokens with each access token's expiry (what kvo plugin token hands a plugin:
// the access token only, never the refresh token).
func AccessTokens(server string, caPEM []byte, st tokenstore.Store, name, lockDir string) func(context.Context) (string, time.Time, error) {
	f := tokens(server, caPEM, st, name, lockDir)
	return func(ctx context.Context) (string, time.Time, error) {
		s, err := f(ctx)
		return s.AccessToken, s.Expiry, err
	}
}

func tokens(server string, caPEM []byte, st tokenstore.Store, name, lockDir string) func(context.Context) (Saved, error) {
	var mu sync.Mutex
	var cached Saved
	return func(ctx context.Context) (Saved, error) {
		mu.Lock()
		defer mu.Unlock()
		if fresh(cached) {
			return cached, nil
		}
		s, err := load(st, name)
		if err != nil {
			return Saved{}, err
		}
		if fresh(s) {
			cached = s
			return s, nil
		}
		unlock, err := lockFile(filepath.Join(lockDir, name+".lock"))
		if err != nil {
			return Saved{}, err
		}
		defer unlock()
		for attempt := 0; attempt < 3; attempt++ {
			if s, err = load(st, name); err != nil { // another command may have refreshed meanwhile
				return Saved{}, err
			}
			if fresh(s) {
				cached = s
				return s, nil
			}
			hc, err := HTTPClient(caPEM)
			if err != nil {
				return Saved{}, err
			}
			cfg := Config(server, "http://127.0.0.1")
			t, err := cfg.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, hc), &oauth2.Token{RefreshToken: s.RefreshToken, Expiry: time.Unix(1, 0)}).Token()
			if err != nil {
				if strings.Contains(err.Error(), "raced") {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				return Saved{}, fmt.Errorf("session ended, run kvo login again (%w)", err)
			}
			if err := Save(st, name, t); err != nil {
				return Saved{}, err
			}
			cached = Saved{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, Expiry: t.Expiry}
			return cached, nil
		}
		return Saved{}, errors.New("couldn't refresh the session")
	}
}
