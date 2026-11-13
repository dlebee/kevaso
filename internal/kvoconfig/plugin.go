package kvoconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/login"
)

// AccessToken is a kvo login context's access token and when it expires, refreshed (and the
// rotated refresh token saved) like any kvo command does. It is what kvo hands a plugin; a context
// with a client certificate has no token to hand out.
func (c Config) AccessToken(ctx context.Context, path, name string) (string, time.Time, error) {
	name, kc, err := c.Resolve(name)
	if err != nil {
		return "", time.Time{}, err
	}
	if !kc.Login {
		return "", time.Time{}, fmt.Errorf("context %s signs in with a client certificate, which kvo never hands to a plugin: use a kvo login context", name)
	}
	ca, err := os.ReadFile(kc.CA)
	if err != nil {
		return "", time.Time{}, err
	}
	servers := client.SplitServers(kc.Server)
	if len(servers) == 0 {
		return "", time.Time{}, fmt.Errorf("context %s has no server", name)
	}
	return login.AccessTokens(servers[0], ca, Tokens(path), name, filepath.Join(filepath.Dir(path), "locks"))(ctx)
}
