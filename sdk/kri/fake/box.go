package fake

import (
	"context"
	"io"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	"kevaso.com/core/sdk/kri"
)

// Box is the fake as a container runtime (docker, podman): init steps in init containers
// (RunInit), file and env secrets from the host (SetSecrets) as the container runtime gives them:
// files in place while it runs (those in a folder it has mounted), variables fixed when its main
// container is made and made afresh at a start when they changed, every value off the host when
// it stops, nothing left when it's deleted.
type Box struct {
	*Runtime
	host map[kri.ID]*boxSecrets
	// InitSaw records, for each init step run, the secret files it found (path → value).
	InitSaw map[string]map[string]string
}

type boxSecrets struct {
	files    map[string][]byte // on the host, by path in the silo
	env      map[string][]byte // the env file, on the host
	envKey   []string          // what the env file holds: NAME=secret@version
	dirs     []string          // folders the files need mounted
	made     bool              // the main container exists
	mainDirs []string          // what it was made with
	mainEnv  map[string][]byte
	mainKey  []string
}

// NewBox returns an empty fake container runtime.
func NewBox() *Box {
	return &Box{Runtime: New(), host: map[kri.ID]*boxSecrets{}, InitSaw: map[string]map[string]string{}}
}

// Info implements kri.Runtime: a container.
func (b *Box) Info() kri.Info {
	i := b.Runtime.Info()
	i.Name, i.Capabilities.Isolation, i.Capabilities.Network, i.Capabilities.Persistence = "fake-box", "container", "netns", "volume"
	return i
}

func boxDirs(files map[string][]byte) []string {
	var dirs []string
	for p := range files {
		dirs = append(dirs, path.Dir(p))
	}
	slices.Sort(dirs)
	return slices.Compact(dirs)
}

func boxCovered(want, have []string) bool {
	for _, w := range want {
		if !slices.ContainsFunc(have, func(h string) bool { return w == h || strings.HasPrefix(w, h+"/") }) {
			return false
		}
	}
	return true
}

func (s *boxSecrets) pending() string {
	if !s.made {
		return ""
	}
	var waits []string
	if !slices.Equal(s.envKey, s.mainKey) {
		waits = append(waits, "environment variables")
	}
	if !boxCovered(s.dirs, s.mainDirs) {
		waits = append(waits, "files in a folder not mounted yet")
	}
	if len(waits) == 0 {
		return ""
	}
	return strings.Join(waits, " and ") + " take effect at the next start"
}

// SetSecrets implements kri.HostSecrets.
func (b *Box) SetSecrets(_ context.Context, id kri.ID, sec kri.Secrets) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("set-secrets", id)
	if _, err := b.get(id); err != nil {
		return "", err
	}
	s := b.host[id]
	if s == nil {
		s = &boxSecrets{}
		b.host[id] = s
	}
	s.files, s.env, s.envKey = map[string][]byte{}, map[string][]byte{}, nil
	for _, f := range sec.Files {
		s.files[f.Path] = slices.Clone(f.Value)
	}
	for _, e := range sec.Env {
		s.env[e.Name] = slices.Clone(e.Value)
		s.envKey = append(s.envKey, e.Name+"="+e.Secret+"@"+strconv.FormatInt(e.Version, 10))
	}
	slices.Sort(s.envKey)
	s.dirs = boxDirs(s.files)
	return s.pending(), nil
}

// Start implements kri.Runtime: the main container made (or made afresh) with its secrets.
func (b *Box) Start(ctx context.Context, id kri.ID) error {
	b.mu.Lock()
	if s := b.host[id]; s != nil {
		if st, ok := b.silos[id]; ok && st.state != kri.Running && (!s.made || s.pending() != "") {
			s.made, s.mainDirs, s.mainEnv, s.mainKey = true, s.dirs, maps.Clone(s.env), s.envKey
			b.record("make-main", id)
		}
	}
	b.mu.Unlock()
	return b.Runtime.Start(ctx, id)
}

func (b *Box) wipe(id kri.ID) {
	if s := b.host[id]; s != nil {
		s.files, s.env = map[string][]byte{}, map[string][]byte{}
	}
}

// Stop implements kri.Runtime: the values go off the host.
func (b *Box) Stop(ctx context.Context, id kri.ID) error {
	err := b.Runtime.Stop(ctx, id)
	b.mu.Lock()
	b.wipe(id)
	b.mu.Unlock()
	return err
}

// Kill implements kri.Killer: the values go off the host.
func (b *Box) Kill(ctx context.Context, id kri.ID) error {
	err := b.Runtime.Kill(ctx, id)
	b.mu.Lock()
	b.wipe(id)
	b.mu.Unlock()
	return err
}

// Delete implements kri.Runtime: nothing of it left on the host.
func (b *Box) Delete(ctx context.Context, id kri.ID) error {
	b.mu.Lock()
	delete(b.host, id)
	b.mu.Unlock()
	return b.Runtime.Delete(ctx, id)
}

// Reset implements kri.Resetter: no main container until the next start.
func (b *Box) Reset(ctx context.Context, spec kri.Spec) error {
	b.mu.Lock()
	if s := b.host[spec.ID]; s != nil {
		s.made, s.mainDirs, s.mainEnv, s.mainKey = false, nil, nil, nil
	}
	b.mu.Unlock()
	return b.Runtime.Reset(ctx, spec)
}

// RunInit implements kri.InitContainers: records the secret files the step finds.
func (b *Box) RunInit(_ context.Context, id kri.ID, step kri.InitStep, _ io.Writer) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("init "+step.Name, id)
	saw := map[string]string{}
	if s := b.host[id]; s != nil {
		for p, v := range s.files {
			saw[p] = string(v)
		}
	}
	b.InitSaw[id.Name+"/"+step.Name] = saw
	return 0, nil
}

// File is what the silo reads at p now ("" and false if nothing): the host's file, if the
// running container has its folder mounted.
func (b *Box) File(id kri.ID, p string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.host[id]
	if s == nil {
		return "", false
	}
	v, ok := s.files[p]
	if !ok || !boxCovered([]string{path.Dir(p)}, s.mainDirs) {
		return "", false
	}
	return string(v), true
}

// Env is the environment variable the silo's command got ("" and false if none).
func (b *Box) Env(id kri.ID, name string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.host[id]
	if s == nil || !s.made {
		return "", false
	}
	v, ok := s.mainEnv[name]
	return string(v), ok
}

// HostValues is how many secret values of the silo are on the host now (files and variables).
func (b *Box) HostValues(id kri.ID) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.host[id]
	if s == nil {
		return 0
	}
	return len(s.files) + len(s.env)
}

// Known reports whether the runtime holds anything of the silo's secrets at all.
func (b *Box) Known(id kri.ID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.host[id]
	return ok
}

var (
	_ kri.HostSecrets    = (*Box)(nil)
	_ kri.InitContainers = (*Box)(nil)
	_ kri.Resetter       = (*Box)(nil)
	_ kri.Killer         = (*Box)(nil)
)
