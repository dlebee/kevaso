// Package fake is an in-memory runtime for tests. It passes the same conformance suite (kritest) as
// real runtimes, so tests built on it can't rely on behaviour a real runtime wouldn't have.
package fake

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"kevaso.com/core/sdk/kri"
)

// Handler answers Exec: output and exit code for a command run in a silo.
type Handler func(id kri.ID, cmd []string, stdin []byte) (stdout string, code int)

// Runtime is the fake. The zero value isn't usable; use New.
type Runtime struct {
	mu    sync.Mutex
	silos map[kri.ID]*silo
	// Handler answers Exec; the default treats `sh -c SCRIPT` as "success, no output", and
	// `exit N` exits with N.
	Handler Handler
	// Program, if set, answers Exec instead of Handler, streaming: it gets the request as is (stdin,
	// stdout, the terminal and its resizes). ctx is cancelled when the exec's client goes away; the
	// fake then counts the command killed and returns at once, as a real runtime must.
	Program         func(ctx context.Context, id kri.ID, req kri.ExecRequest) int
	running, killed int
	// Calls records every operation, for tests that check what the agent did.
	Calls []string
	// FailCreate makes Create fail for these silo names (to test error handling).
	FailCreate map[string]error
}

type silo struct {
	spec  kri.Spec
	state kri.State
}

// New returns an empty fake runtime.
func New() *Runtime {
	return &Runtime{silos: map[kri.ID]*silo{}, FailCreate: map[string]error{}}
}

func (r *Runtime) record(op string, id kri.ID) { r.Calls = append(r.Calls, op+" "+id.String()) }

// Info implements kri.Runtime.
func (r *Runtime) Info() kri.Info {
	return kri.Info{Name: "fake", Version: "test", Capabilities: kri.Capabilities{
		Isolation: "vm", Network: "nic", UDP: true, InboundServices: true, Persistence: "disk", Exec: true,
	}}
}

// Create implements kri.Runtime.
func (r *Runtime) Create(_ context.Context, spec kri.Spec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record("create", spec.ID)
	if err := r.FailCreate[spec.ID.Name]; err != nil {
		return err
	}
	if _, ok := r.silos[spec.ID]; ok {
		return nil
	}
	r.silos[spec.ID] = &silo{spec: spec, state: kri.Created}
	return nil
}

func (r *Runtime) get(id kri.ID) (*silo, error) {
	s, ok := r.silos[id]
	if !ok {
		return nil, fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	return s, nil
}

// Start implements kri.Runtime.
func (r *Runtime) Start(_ context.Context, id kri.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record("start", id)
	s, err := r.get(id)
	if err != nil {
		return err
	}
	s.state = kri.Running
	return nil
}

// Stop implements kri.Runtime.
func (r *Runtime) Stop(_ context.Context, id kri.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record("stop", id)
	s, err := r.get(id)
	if err != nil {
		return err
	}
	if s.state == kri.Running {
		s.state = kri.Stopped
	}
	return nil
}

// Delete implements kri.Runtime.
func (r *Runtime) Delete(_ context.Context, id kri.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record("delete", id)
	delete(r.silos, id)
	return nil
}

// Reset implements kri.Resetter: a fresh copy from spec.Image, Created.
func (r *Runtime) Reset(_ context.Context, spec kri.Spec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record("reset", spec.ID)
	if _, err := r.get(spec.ID); err != nil {
		return err
	}
	r.silos[spec.ID] = &silo{spec: spec, state: kri.Created}
	return nil
}

// Image is the image a silo was created or last reset with ("" if absent).
func (r *Runtime) Image(id kri.ID) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.silos[id]; ok {
		return s.spec.Image
	}
	return ""
}

// Status implements kri.Runtime.
func (r *Runtime) Status(_ context.Context, id kri.ID) (kri.Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.silos[id]
	if !ok {
		return kri.Status{State: kri.Absent}, nil
	}
	st := kri.Status{State: s.state}
	if s.state == kri.Running {
		st.Address = "10.64.0." + fmt.Sprint(1+len(id.Name)%250)
	}
	return st, nil
}

// List implements kri.Runtime.
func (r *Runtime) List(context.Context) ([]kri.ID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]kri.ID, 0, len(r.silos))
	for id := range r.silos {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	return ids, nil
}

// Exec implements kri.Runtime.
func (r *Runtime) Exec(ctx context.Context, id kri.ID, req kri.ExecRequest) (int, error) {
	r.mu.Lock()
	s, err := r.get(id)
	if err == nil && s.state != kri.Running {
		err = fmt.Errorf("%s is %s, not running", id, s.state)
	}
	h, p := r.Handler, r.Program
	if err == nil && p != nil {
		r.running++
	}
	r.mu.Unlock()
	if err != nil {
		return -1, err
	}
	if p != nil {
		return r.runProgram(ctx, id, req, p)
	}
	var stdin []byte
	if req.Stdin != nil {
		stdin, _ = io.ReadAll(req.Stdin)
	}
	if h == nil {
		h = defaultHandler
	}
	out, code := h(id, req.Command, stdin)
	if req.Stdout != nil {
		_, _ = io.WriteString(req.Stdout, out)
	}
	return code, nil
}

func (r *Runtime) runProgram(ctx context.Context, id kri.ID, req kri.ExecRequest, p func(context.Context, kri.ID, kri.ExecRequest) int) (int, error) {
	done := make(chan int, 1)
	go func() { done <- p(ctx, id, req) }()
	select {
	case code := <-done:
		r.mu.Lock()
		r.running--
		r.mu.Unlock()
		return code, nil
	case <-ctx.Done():
		r.mu.Lock()
		r.running--
		r.killed++
		r.mu.Unlock()
		return -1, ctx.Err()
	}
}

// Running is how many Program commands are running now.
func (r *Runtime) Running() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// Killed is how many Program commands were stopped because their client went away.
func (r *Runtime) Killed() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.killed
}

func defaultHandler(_ kri.ID, cmd []string, _ []byte) (string, int) {
	line := strings.Join(cmd, " ")
	var code int
	if _, err := fmt.Sscanf(lastField(line), "%d", &code); err == nil && strings.Contains(line, "exit ") {
		return "", code
	}
	if len(cmd) > 0 && cmd[0] == "echo" {
		return strings.Join(cmd[1:], " ") + "\n", 0
	}
	return "", 0
}

func lastField(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return strings.Trim(f[len(f)-1], "'\"")
}

var _ kri.Runtime = (*Runtime)(nil)
