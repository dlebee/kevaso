package client

// The control plane's OIDC issuer, as clients see it (the server is internal/issuer).
const (
	OIDCClientID  = "kvo" // kvo is a public client: no secret, loopback redirects only
	OIDCAudience  = "kevaso"
	PathDiscovery = "/.well-known/openid-configuration"
	PathKeys      = "/oidc/keys"
	PathAuthorize = "/oidc/authorize"
	PathLogin     = "/oidc/login"
	PathToken     = "/oidc/token"
)
