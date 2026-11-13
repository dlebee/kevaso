// Package version is kevasod's own version, set at build time:
//
//	go build -ldflags "-X kevaso.com/core/internal/version.Version=v0.3.1" ./cmd/kevasod
//
// Hosts report it (Host status.version) and kvoadm upgrade plans from it (ADR 0006).
package version

// Version is this build's version: a semantic version with a leading v.
var Version = "v0.0.0-dev"
