package container

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// Pulls (design §0.2, "Private registries"). The agent pulls a silo's image before Create and
// Reset, with the credential the control plane gave it for that pull. The credential goes into a
// throwaway auth file under PullDir (tmpfs: /run), named for this pull only and removed right
// after, which the engine is pointed at for that one command (docker --config DIR, podman
// --authfile FILE). It's never on a command line, never in the engine's own config
// (~/.docker/config.json, containers/auth.json), and never in the container: Start and init
// containers run what's already pulled (--pull never).

// PullDir is where throwaway auth files live, on tmpfs. Each pull has a directory of its own
// (0700), removed when the pull ends, whatever happens.
var PullDir = "/run/kevaso-pull"

// dockerHubAuthKey is how docker's config names Docker Hub.
const dockerHubAuthKey = "https://index.docker.io/v1/"

// AuthFile is the auth file's contents for one credential: docker's config.json and podman's
// auth.json share the {"auths": {SERVER: {"auth": base64(user:password)}}} shape.
func AuthFile(engine string, auth *kri.RegistryAuth) ([]byte, error) {
	key := auth.Server
	if engine != "podman" && key == v1.DockerHub {
		key = dockerHubAuthKey
	}
	cred := make([]byte, 0, len(auth.Username)+1+len(auth.Password))
	cred = append(append(append(cred, auth.Username...), ':'), auth.Password...)
	defer clear(cred)
	return json.Marshal(map[string]any{"auths": map[string]any{key: map[string]string{"auth": base64.StdEncoding.EncodeToString(cred)}}})
}

// PullArgs is the engine command for one pull, with the auth file at dir (none: anonymous).
func PullArgs(engine, dir, ref string) []string {
	switch {
	case dir == "":
		return []string{"pull", "--quiet", ref}
	case engine == "podman":
		return []string{"pull", "--quiet", "--authfile", dir + "/auth.json", ref}
	}
	return []string{"--config", dir, "pull", "--quiet", ref}
}

// Pull implements kri.Puller.
func (r *Runtime) Pull(ctx context.Context, id kri.ID, image string, auth *kri.RegistryAuth) (string, error) {
	ref := ImageRef(image)
	dir := ""
	if auth != nil {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		dir = PullDir + "/" + NamesFor(id).Short + "-" + hex.EncodeToString(b)
		defer func() { _ = r.Host.RemoveAll(dir) }() // first: even a failed write leaves nothing
		file, err := AuthFile(r.engine(), auth)
		if err != nil {
			return "", err
		}
		name := "/config.json"
		if r.engine() == "podman" {
			name = "/auth.json"
		}
		err = r.Host.WriteFile(dir+name, file, 0o600)
		clear(file)
		if err != nil {
			return "", err
		}
	}
	if _, err := r.eng(ctx, nil, PullArgs(r.engine(), dir, ref)...); err != nil {
		return "", &kri.PullError{Image: ref, Reason: pullReason(err)}
	}
	return r.digest(ctx, ref), nil
}

// pullReason is the engine's own words about a failed pull (its stderr: the registry's reason).
func pullReason(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": exit "); i >= 0 {
		if j := strings.Index(msg[i+2:], ": "); j >= 0 {
			return strings.TrimSpace(msg[i+2+j+2:])
		}
	}
	return msg
}

// digest is the digest ref has locally: the RepoDigests entry for its repository ("" if the engine
// doesn't say).
func (r *Runtime) digest(ctx context.Context, ref string) string {
	out, err := r.eng(ctx, nil, "image", "inspect", "--format", "{{json .RepoDigests}}", ref)
	if err != nil {
		return ""
	}
	var digests []string
	if json.Unmarshal([]byte(strings.TrimSpace(string(out))), &digests) != nil {
		return ""
	}
	return PickDigest(ref, digests)
}

// PickDigest picks ref's digest among an image's RepoDigests (repo@sha256:…): the one for ref's
// repository, else the first. Pure.
func PickDigest(ref string, repoDigests []string) string {
	want, err := v1.ParseImageRef(ref)
	first := ""
	for _, rd := range repoDigests {
		i := strings.LastIndex(rd, "@")
		if i < 0 {
			continue
		}
		d := rd[i+1:]
		if first == "" {
			first = d
		}
		if got, perr := v1.ParseImageRef(rd); err == nil && perr == nil && got.Registry == want.Registry && got.Repository == want.Repository {
			return d
		}
	}
	return first
}

var _ kri.Puller = (*Runtime)(nil)
