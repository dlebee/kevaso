package container

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/container/ocienv"
	"kevaso.com/core/sdk/kri"
)

// File and env secrets on containers (design §8.5, ADR 0009 and its addendum): the host delivers
// them with nothing of Kevaso's in the container and nothing written into it.
//
// Files. Each silo has a tmpfs of the host's own at SecretsDir/SHORT (0700, root's, memory only:
// never the host's disk, the container's writable layer or an image), mounted by the runtime. A
// file at /run/a/b in the silo is FILES/run/a/b in it, written by the host (0400, root's;
// atomically: a new file renamed over the old), and the folder /run/a is bind-mounted read-only
// into the container (`--mount type=bind,…,readonly`: the container can't write there, so it can't
// plant a link the host would follow). The main container and its init containers get those
// mounts, so a file is there before the silo's command (and its init steps) start. A rotated value
// is renamed into the folder the container has mounted: it changes in place, with no restart. A
// file in a folder the running container doesn't have mounted waits for its next start (a mount
// can't be added to a running container). docker inspect shows the mounts' folders, never a value.
//
// Variables. Each silo's go in an env file in the same tmpfs (FILES' sibling env, 0600: never on a
// command line, so never in the host's process listing), and reach its containers one of two ways:
//
//   - Through Kevaso's OCI runtime (viaRuntime; ocienv), where Install could put it in front of the
//     engine's runc (docker, rootful, runc its default, API 1.43+). The container is made with
//     `--runtime kevaso-oci --annotation kevaso.com/env-secrets=SHORT` and no variable: at each
//     start the engine's shim calls kevaso-oci as it would runc, which reads the env file and sets
//     the variables in the bundle's process.env (in memory, under /run) before handing over to
//     runc. The engine's records (inspect, config.v2.json, containerd's metadata) never have the
//     values. A rotated variable takes effect at the next start, without the container being made
//     afresh (each start reads the file). `docker exec` (kvo exec) processes don't get them: the
//     engine makes an exec's environment from its own config.
//   - Through --env-file (viaEnvFile), everywhere else (podman, whose bundle config.json is on the
//     host's disk; rootless docker; a non-runc default; a failed registration). The engine keeps
//     the values in the container's config, so `docker inspect` shows them (Config.Env) to anyone
//     with the host's engine, and the engine stores that config on the host's disk (docker:
//     /var/lib/docker/containers/ID/config.v2.json; podman: its containers database). The admission
//     warning and SecretsDelivered say so. A rotated variable takes effect at the next start: Start
//     makes the main container afresh (from its image, volumes kept, its writable layer not).
//
// Either way a variable set by a secret wins over the same name from the image (the engine puts a
// container's variables over its image's; kevaso-oci replaces the name in process.env, the image's
// and Kevaso's own CA variables alike). A silo whose way changes (the host's runtime set up, or gone) is made afresh at its
// next start.
//
// Stop and Kill take every value out of the tmpfs (the files and the env file; folders stay,
// empty, for the stopped container's mounts; the engine keeps the variables it was made with); the agent sets them again before the next start. Delete
// unmounts the tmpfs. A silo that moves gets its secrets on its new host the same way, and Delete
// on the old one leaves nothing there.

// SecretsDir is where each silo's secrets tmpfs is mounted, on the host.
var SecretsDir = "/run/kevaso-secrets"

// secretsSize is the size of each silo's secrets tmpfs (memory only as it's used).
const secretsSize = "16m"

// secretState is what the runtime knows of a silo's secrets: paths, names and versions, never a
// value (state.json is on the host's disk).
type secretState struct {
	Files []string `json:"files,omitempty"` // paths in the silo
	Dirs  []string `json:"dirs,omitempty"`  // the folders those need mounted
	Env   []string `json:"env,omitempty"`   // NAME=secret@version, sorted
	// EnvVia is how the variables reach the next container made: viaRuntime or viaEnvFile.
	EnvVia string `json:"envVia,omitempty"`
	// What the main container was made with (it keeps its mounts, and with an env file its
	// variables, until it's made again; through the runtime it gets the variables at each start).
	MainDirs []string `json:"mainDirs,omitempty"`
	MainEnv  []string `json:"mainEnv,omitempty"`
	MainVia  string   `json:"mainVia,omitempty"`
}

// How env secrets reach a container.
const (
	// viaRuntime: Kevaso's OCI runtime (ocienv) puts them in the process's environment as the
	// container starts, from the host's tmpfs; the engine never has them.
	viaRuntime = "runtime"
	// viaEnvFile: --env-file; the engine keeps them in the container's config (inspect, its disk).
	viaEnvFile = "env-file"
)

// setEnvPath is Install's decision for this host: through Kevaso's OCI runtime, or (why) not.
func (r *Runtime) setEnvPath(shim bool, why string) {
	r.envMu.Lock()
	defer r.envMu.Unlock()
	r.envPlanned, r.envShim, r.envWhy = true, shim, why
}

func (r *Runtime) envShimNow() (shim bool, why string) {
	r.envMu.Lock()
	defer r.envMu.Unlock()
	if !r.envPlanned {
		return false, "the runtime isn't installed yet"
	}
	return r.envShim, r.envWhy
}

// viaFor is how a silo's variables are to reach its next container. Before Install has decided
// (kevasod just started), a silo keeps the way it had, so it isn't made afresh for nothing.
func (r *Runtime) viaFor(cur secretState) string {
	r.envMu.Lock()
	defer r.envMu.Unlock()
	switch {
	case !r.envPlanned && cur.EnvVia != "":
		return cur.EnvVia
	case r.envPlanned && r.envShim:
		return viaRuntime
	}
	return viaEnvFile
}

// EnvInEngine implements kri.EnvPath: whether the engine has the silo's variables, and why.
func (r *Runtime) EnvInEngine(id kri.ID) (bool, string) {
	s, ok := r.load(id)
	if ok && s.Secrets != nil && s.Secrets.EnvVia == viaRuntime {
		return false, ""
	}
	_, why := r.envShimNow()
	if why == "" {
		why = "the silo's container was made before Kevaso's OCI runtime was set up here"
	}
	return true, why
}

// mainVia is how the main container got its variables ("" with none).
func (s secretState) mainVia() string {
	if s.MainVia == "" && len(s.MainEnv) > 0 {
		return viaEnvFile
	}
	return s.MainVia
}

// SecretsPaths are a silo's secrets folders on the host: the tmpfs, the files' tree, the env file.
func SecretsPaths(id kri.ID) (tmpfs, files, env string) {
	t := SecretsDir + "/" + NamesFor(id).Short
	return t, t + "/files", t + "/env"
}

// SecretDirs are the folders to mount for files at paths: each file's folder, without those inside
// another one (mounted with it). Sorted. Pure.
func SecretDirs(paths []string) []string {
	var dirs []string
	for _, p := range paths {
		dirs = append(dirs, path.Dir(p))
	}
	sort.Strings(dirs)
	var out []string
	for _, d := range dirs {
		if len(out) > 0 && within(d, out[len(out)-1]) {
			continue
		}
		out = append(out, d)
	}
	return out
}

// within reports whether p is dir or inside it.
func within(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

// covered reports whether every folder in want is mounted by one of have.
func covered(want, have []string) bool {
	for _, w := range want {
		if !slices.ContainsFunc(have, func(h string) bool { return within(w, h) }) {
			return false
		}
	}
	return true
}

// checkEnv says why a variable can't go in the env file (and, via, to the container).
func (r *Runtime) checkEnv(e kri.SecretEnv, via string) error {
	if !validEnvName(e.Name) {
		return fmt.Errorf("secret %s: %q isn't a variable name", e.Secret, e.Name)
	}
	if bytes.ContainsAny(e.Value, "\n\x00") {
		return fmt.Errorf("secret %s: its value has a newline or a NUL, which %s can't take as an environment variable: deliver it as a file", e.Secret, r.engine())
	}
	if via == viaRuntime && !utf8.Valid(e.Value) {
		return fmt.Errorf("secret %s: its value isn't UTF-8 text, which an OCI config (JSON) can't carry: deliver it as a file", e.Secret)
	}
	// podman's env-file reader takes a quoted value as quoted (and unquotes it): refused rather
	// than changed on the way.
	if r.engine() == "podman" && len(e.Value) > 0 && (e.Value[0] == '"' || e.Value[0] == '\'') {
		return fmt.Errorf("secret %s: its value starts with a quote, which podman would strip from an environment variable: deliver it as a file", e.Secret)
	}
	return nil
}

func validEnvName(n string) bool {
	if n == "" {
		return false
	}
	for i, c := range n {
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// SetSecrets implements kri.HostSecrets.
func (r *Runtime) SetSecrets(ctx context.Context, id kri.ID, sec kri.Secrets) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.load(id)
	if !ok {
		return "", fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	var paths []string
	seen := map[string]bool{}
	for _, f := range sec.Files {
		if why := v1.ContainerFileProblem(f.Path); why != "" {
			return "", fmt.Errorf("secret %s: %s", f.Secret, why)
		}
		if seen[f.Path] {
			return "", fmt.Errorf("secret %s: %s is delivered twice", f.Secret, f.Path)
		}
		seen[f.Path] = true
		paths = append(paths, f.Path)
	}
	cur := secretState{}
	if s.Secrets != nil {
		cur = *s.Secrets
	}
	via := ""
	if len(sec.Env) > 0 {
		via = r.viaFor(cur)
	}
	var env []string
	for _, e := range sec.Env {
		if err := r.checkEnv(e, via); err != nil {
			return "", err
		}
		env = append(env, e.Name+"="+e.Secret+"@"+strconv.FormatInt(e.Version, 10))
	}
	sort.Strings(paths)
	sort.Strings(env)
	next := secretState{Files: paths, Dirs: SecretDirs(paths), Env: env, EnvVia: via, MainDirs: cur.MainDirs, MainEnv: cur.MainEnv, MainVia: cur.MainVia}
	tmpfs, files, envFile := SecretsPaths(id)
	if len(paths) > 0 || len(env) > 0 || len(cur.MainDirs) > 0 {
		if err := r.mountSecrets(ctx, tmpfs); err != nil {
			return "", err
		}
	}
	for _, f := range sec.Files {
		if err := r.Host.WriteFile(files+f.Path, f.Value, fileMode(f.Mode)); err != nil {
			return "", fmt.Errorf("secret %s: %w", f.Secret, err)
		}
	}
	for _, p := range cur.Files {
		if !seen[p] {
			if err := r.Host.RemoveAll(files + p); err != nil {
				return "", err
			}
		}
	}
	if len(sec.Env) > 0 {
		text := envFileText(sec.Env)
		err := r.Host.WriteFile(envFile, text, 0o600)
		clear(text)
		if err != nil {
			return "", fmt.Errorf("env secrets: %w", err)
		}
	} else if err := r.Host.RemoveAll(envFile); err != nil {
		return "", err
	}
	if err := r.ensureSecretDirs(ctx, id, next); err != nil {
		return "", err
	}
	if len(paths) == 0 && len(env) == 0 && len(cur.MainDirs) == 0 {
		if err := r.unmountSecrets(ctx, id); err != nil {
			return "", err
		}
	}
	if len(next.Files)+len(next.Env)+len(next.MainDirs)+len(next.MainEnv) == 0 && next.MainVia == "" {
		s.Secrets = nil
	} else {
		s.Secrets = &next
	}
	if err := r.save(s); err != nil {
		return "", err
	}
	st, _, err := r.inspect(ctx, NamesFor(id).Main)
	if err != nil || st == "" {
		return "", err // no main container yet: Start makes it with all of them
	}
	return next.pending(), nil
}

// pending says what the main container doesn't have yet, which waits for its next start.
func (s secretState) pending() string {
	var waits []string
	if !slices.Equal(s.Env, s.MainEnv) || s.EnvVia != s.mainVia() {
		waits = append(waits, "environment variables")
	}
	if !covered(s.Dirs, s.MainDirs) {
		waits = append(waits, "files in a folder not mounted yet")
	}
	if len(waits) == 0 {
		return ""
	}
	return strings.Join(waits, " and ") + " take effect at the next start"
}

// remake reports whether the main container must be made afresh for its secrets: a folder it
// doesn't have mounted, its variables going another way (an env file, Kevaso's runtime, none:
// the runtime and its annotation are set when it's made), or with an env file, changed variables.
// Through the runtime, changed variables need no remake: every start reads them afresh.
func (s *secretState) remake() bool {
	if s == nil {
		return false
	}
	return !covered(s.Dirs, s.MainDirs) || s.EnvVia != s.mainVia() || s.EnvVia == viaEnvFile && !slices.Equal(s.Env, s.MainEnv)
}

// started records what the main container has now that it started.
func (s *secretState) started() {
	if s != nil {
		s.MainDirs, s.MainEnv, s.MainVia = s.Dirs, s.Env, s.EnvVia
	}
}

func fileMode(m uint32) os.FileMode {
	if m == 0 {
		return 0o400
	}
	return os.FileMode(m & 0o777)
}

// envFileText is the engine's env file: NAME=VALUE lines (checked: no newline or NUL in a value).
func envFileText(env []kri.SecretEnv) []byte {
	sorted := slices.Clone(env)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b bytes.Buffer
	for _, e := range sorted {
		b.WriteString(e.Name)
		b.WriteByte('=')
		b.Write(e.Value)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// mounted reports whether a tmpfs is mounted at dir (from the host's mount table).
func (r *Runtime) mounted(dir string) bool {
	b, err := r.Host.ReadFile("/proc/self/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == dir && f[2] == "tmpfs" {
			return true
		}
	}
	return false
}

// mountSecrets has the silo's secrets tmpfs mounted (again after a host reboot).
func (r *Runtime) mountSecrets(ctx context.Context, tmpfs string) error {
	if r.mounted(tmpfs) {
		return nil
	}
	if _, err := r.cmd(ctx, nil, "mkdir", "-p", "-m", "0700", tmpfs); err != nil {
		return err
	}
	_, err := r.cmd(ctx, nil, "mount", "-t", "tmpfs", "-o", "size="+secretsSize+",mode=0700,uid=0,gid=0,nosuid,nodev,noexec", "kevaso-secrets", tmpfs)
	return err
}

// unmountSecrets takes the silo's secrets tmpfs away, with everything in it.
func (r *Runtime) unmountSecrets(ctx context.Context, id kri.ID) error {
	tmpfs, _, _ := SecretsPaths(id)
	if r.mounted(tmpfs) {
		if _, err := r.cmd(ctx, nil, "umount", tmpfs); err != nil {
			return err
		}
	}
	return r.Host.RemoveAll(tmpfs)
}

// ensureSecretDirs has every folder the containers mount (wanted, or the main container's) there,
// so a mount never lacks its source: the engine would refuse to start, or (docker -v) make one on
// the host's disk.
func (r *Runtime) ensureSecretDirs(ctx context.Context, id kri.ID, s secretState) error {
	_, files, _ := SecretsPaths(id)
	dirs := append(slices.Clone(s.Dirs), s.MainDirs...)
	if len(dirs) == 0 {
		return nil
	}
	args := []string{"-p", "-m", "0700"}
	for _, d := range dirs {
		args = append(args, files+d)
	}
	_, err := r.cmd(ctx, nil, "mkdir", args...)
	return err
}

// wipeSecrets takes every value out of the tmpfs (a stopped silo has none there); folders stay.
func (r *Runtime) wipeSecrets(s state) error {
	if s.Secrets == nil {
		return nil
	}
	_, files, envFile := SecretsPaths(s.ID)
	for _, p := range s.Secrets.Files {
		if err := r.Host.RemoveAll(files + p); err != nil {
			return err
		}
	}
	return r.Host.RemoveAll(envFile)
}

// secretArgs are a container's secret mounts and env file.
func secretArgs(s state) []string {
	if s.Secrets == nil {
		return nil
	}
	_, files, envFile := SecretsPaths(s.ID)
	var args []string
	for _, d := range s.Secrets.Dirs {
		args = append(args, "--mount", "type=bind,src="+files+d+",dst="+d+",readonly")
	}
	switch {
	case len(s.Secrets.Env) == 0:
	case s.Secrets.EnvVia == viaRuntime:
		// Kevaso's OCI runtime reads the variables from the host's tmpfs at each start: the
		// annotation names whose, never a value.
		args = append(args, "--runtime", ocienv.RuntimeName, "--annotation", ocienv.Annotation+"="+NamesFor(s.ID).Short)
	default:
		args = append(args, "--env-file", envFile)
	}
	return args
}

// prepareSecrets has what a container about to be made or started mounts there: the tmpfs and
// its folders (after a host reboot too), and the env file when the container is to be made with
// it. Without the values (SetSecrets wasn't called since the last stop) a container is never made:
// it would start without its secrets.
func (r *Runtime) prepareSecrets(ctx context.Context, s state, making bool) error {
	if s.Secrets == nil {
		return nil
	}
	tmpfs, files, envFile := SecretsPaths(s.ID)
	if err := r.mountSecrets(ctx, tmpfs); err != nil {
		return err
	}
	if err := r.ensureSecretDirs(ctx, s.ID, *s.Secrets); err != nil {
		return err
	}
	there := func(p string) error {
		b, err := r.Host.ReadFile(p)
		clear(b)
		return err
	}
	for _, p := range s.Secrets.Files {
		if err := there(files + p); err != nil {
			return fmt.Errorf("%s: its secret %s isn't on the host (its secrets are set before it starts): %w", s.ID, p, err)
		}
	}
	// Through Kevaso's runtime the variables are read at every start, not only when it's made.
	if len(s.Secrets.Env) > 0 && (making || s.Secrets.EnvVia == viaRuntime) {
		if err := there(envFile); err != nil {
			return fmt.Errorf("%s: its env secrets aren't on the host (its secrets are set before it starts): %w", s.ID, err)
		}
	}
	return nil
}
