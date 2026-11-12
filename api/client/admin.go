package client

import "time"

// Wire types of the endpoints outside the object API.

// InviteRequest asks for a one-time sign-in code for a user (POST /admin/invites).
type InviteRequest struct {
	User   string   `json:"user"`
	Groups []string `json:"groups,omitempty"`
	TTL    string   `json:"ttl,omitempty"` // default 15m
}

// InviteResponse carries the code (shown once), and what the person needs to pin the cluster.
type InviteResponse struct {
	User          string    `json:"user"`
	Code          string    `json:"code"`
	Expires       time.Time `json:"expires"`
	CAFingerprint string    `json:"caFingerprint"`
}

// User is someone who can sign in (GET /admin/users).
type User struct {
	Name     string    `json:"name"`
	Groups   []string  `json:"groups,omitempty"`
	Disabled bool      `json:"disabled,omitempty"`
	Created  time.Time `json:"created"`
}

// WhoAmI answers GET /auth/whoami.
type WhoAmI struct {
	Type   string   `json:"type"` // user | serviceaccount | host
	Name   string   `json:"name"`
	Role   string   `json:"role,omitempty"` // hosts and certificate users
	Groups []string `json:"groups,omitempty"`
}

// CanIResponse answers GET /auth/can-i.
type CanIResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// TokenRequest asks for a service account token (POST …/serviceaccounts/NAME/token).
type TokenRequest struct {
	Duration string `json:"duration,omitempty"` // default 1h, at most 2160h (90 days)
}

// TokenResponse is the token; it's shown once and works until it expires or the account is deleted.
type TokenResponse struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}
