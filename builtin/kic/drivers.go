// Package kic holds the built-in ingress drivers (sdk/kic): nginx, caddy and kong.
package kic

import (
	"kevaso.com/core/builtin/kic/caddy"
	"kevaso.com/core/builtin/kic/kong"
	"kevaso.com/core/builtin/kic/nginx"
	"kevaso.com/core/sdk/kic"
)

// Builtin is every built-in driver, by name.
func Builtin() kic.Registry {
	return kic.Registry{"nginx": nginx.Driver{}, "caddy": caddy.Driver{}, "kong": kong.Driver{}}
}
