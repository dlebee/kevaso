// Package api is the root of the kevaso.com/core/api module: the kevaso/v1 types (v1), object
// metadata (meta), and, as milestones land, the typed client, informers, the controller runtime and
// the fakes used by tests. It is its own Go module so that plugins and tools can import it without
// pulling in the server's dependencies.
package api
