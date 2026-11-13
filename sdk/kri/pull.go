package kri

import (
	"context"
	"errors"
)

// RegistryAuth is a credential for one pull from a private registry. The runtime gives it to its
// engine for that pull alone: never on a command line, never left in the engine's own config,
// never inside the silo.
type RegistryAuth struct {
	Server   string // the registry host, e.g. ghcr.io (docker.io for Docker Hub)
	Username string
	Password []byte // the caller clears it after the pull
}

// Puller is a runtime that pulls registry images itself (docker, podman), so the agent can hand
// it a credential for one pull and learn what it got. The agent pulls before Create and Reset;
// after that, the runtime never pulls on its own (init containers and the main container run the
// image already pulled), so every pull goes through here.
type Puller interface {
	// Pull fetches image (spec.Image, as Create gets it) and returns the digest it now has locally
	// (sha256:…; "" for an image the runtime builds itself). auth may be nil (an anonymous pull).
	Pull(ctx context.Context, id ID, image string, auth *RegistryAuth) (digest string, err error)
}

// PullError is a pull the registry refused or couldn't serve; Reason is the engine's own words
// (the registry's reason), with no credential in it.
type PullError struct {
	Image  string
	Reason string
}

func (e *PullError) Error() string { return "pull " + e.Image + ": " + e.Reason }

// IsPullError reports whether err is a failed pull.
func IsPullError(err error) bool {
	var p *PullError
	return errors.As(err, &p)
}
