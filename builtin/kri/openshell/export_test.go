package openshell

import (
	"context"
	"os"
	"sync"
)

// TestHost is the in-memory OpenShell host, safe for the agent to call from several goroutines.
// Born is the policy file at the moment `sandbox create` ran: the rules the sandbox was created with.
type TestHost struct {
	fake     *fake
	mu       sync.Mutex
	atCreate string
}

// NewTestHost returns a host with no sandboxes.
func NewTestHost() *TestHost { return &TestHost{fake: newFake()} }

// Runtime is an OpenShell runtime whose commands go through h.
func (h *TestHost) Runtime() *Runtime {
	rt := newRuntime(h.fake, "")
	rt.Host = h
	return rt
}

// Born is the policy file contents passed to sandbox create ("" until then).
func (h *TestHost) Born() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.atCreate
}

// Commands is every command the runtime has run, for failure output.
func (h *TestHost) Commands() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := ""
	for i, c := range h.fake.cmds {
		if i > 0 {
			out += "\n"
		}
		out += c
	}
	return out
}

func (h *TestHost) Run(ctx context.Context, c Cmd) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c.Name == "openshell" && len(c.Args) >= 2 && c.Args[0] == "sandbox" && c.Args[1] == "create" {
		for i, a := range c.Args {
			if a == "--policy" && i+1 < len(c.Args) {
				h.atCreate = string(h.fake.files[c.Args[i+1]])
			}
		}
	}
	return h.fake.Run(ctx, c)
}

func (h *TestHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fake.WriteFile(path, data, mode)
}

func (h *TestHost) ReadFile(path string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fake.ReadFile(path)
}

func (h *TestHost) RemoveAll(path string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fake.RemoveAll(path)
}

func (h *TestHost) Glob(pattern string) ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fake.Glob(pattern)
}
