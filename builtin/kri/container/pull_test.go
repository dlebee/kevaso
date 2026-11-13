package container

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// A pull with a credential: the engine is pointed at a throwaway auth file under PullDir for that
// one command, the password is never on its command line, and nothing is left behind after,
// whether the pull worked or not. Docker and podman each get their own form.
func TestPullWithCredential(t *testing.T) {
	ctx := context.Background()
	const pw = "s3cret-token"
	digest := "sha256:" + strings.Repeat("c4", 32)
	for _, tc := range []struct {
		engine, file, flag string
		key                string
	}{
		{"docker", "config.json", "--config", "ghcr.io"},
		{"podman", "auth.json", "--authfile", "ghcr.io"},
	} {
		t.Run(tc.engine, func(t *testing.T) {
			f := newFake()
			r := runtime(t, f)
			r.Engine = tc.engine
			ref := "ghcr.io/acme/api:v1"
			f.digests[ref] = `["ghcr.io/acme/other@sha256:` + strings.Repeat("0", 64) + `","ghcr.io/acme/api@` + digest + `"]`
			var seen []byte
			var seenArgs []string
			f.onPull = func(engine string, args []string) (int, error) {
				seenArgs = args
				// While the pull runs, its auth file is there, and only there.
				for p, b := range f.files {
					if strings.HasPrefix(p, PullDir+"/") && strings.HasSuffix(p, "/"+tc.file) {
						seen = b
					}
				}
				return 0, nil
			}
			auth := &kri.RegistryAuth{Server: "ghcr.io", Username: "bot", Password: []byte(pw)}
			got, err := r.Pull(ctx, silo, ref, auth)
			if err != nil || got != digest {
				t.Fatalf("pull: %q %v, want %s", got, err, digest)
			}
			var cfg struct {
				Auths map[string]struct{ Auth string } `json:"auths"`
			}
			if json.Unmarshal(seen, &cfg) != nil {
				t.Fatalf("no auth file during the pull (files: %v)", f.files)
			}
			dec, _ := base64.StdEncoding.DecodeString(cfg.Auths[tc.key].Auth)
			if string(dec) != "bot:"+pw {
				t.Fatalf("auth file %s", seen)
			}
			line := strings.Join(seenArgs, " ")
			if strings.Contains(line, pw) || !strings.Contains(line, tc.flag+" "+PullDir+"/") || !strings.HasSuffix(line, "pull --quiet "+ref) &&
				!strings.HasSuffix(line, tc.file+" "+ref) {
				t.Fatalf("pull command %q", line)
			}
			for p := range f.files {
				if strings.HasPrefix(p, PullDir) {
					t.Fatalf("left behind: %s", p)
				}
			}
			for _, c := range f.cmds {
				if strings.Contains(c, pw) || strings.Contains(c, base64.StdEncoding.EncodeToString([]byte("bot:"+pw))) {
					t.Fatalf("the credential on a command line: %s", c)
				}
			}
		})
	}
}

// A refused pull is a kri.PullError with the registry's reason (no credential in it), and leaves
// no auth file either.
func TestPullRefused(t *testing.T) {
	f := newFake()
	r := runtime(t, f)
	f.onPull = func(string, []string) (int, error) { return 1, nil }
	_, err := r.Pull(context.Background(), silo, "ghcr.io/acme/api:v1", &kri.RegistryAuth{Server: "ghcr.io", Username: "bot", Password: []byte("pw-xyz")})
	if !kri.IsPullError(err) || !strings.Contains(err.Error(), "denied: requested access to the resource is denied") || strings.Contains(err.Error(), "pw-xyz") {
		t.Fatalf("err %v", err)
	}
	for p := range f.files {
		if strings.HasPrefix(p, PullDir) {
			t.Fatalf("left behind: %s", p)
		}
	}
}

// Without a credential, a plain pull; Kevaso's own images are never pulled; Docker Hub has its
// own key in docker's config.
func TestPullAnonymousAndOwn(t *testing.T) {
	f := newFake()
	r := runtime(t, f)
	var lines []string
	f.onPull = func(_ string, a []string) (int, error) { lines = append(lines, strings.Join(a, " ")); return 0, nil }
	if _, err := r.Pull(context.Background(), silo, "ubuntu-24.04", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Pull(context.Background(), silo, "kevaso-ingress", nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, "|") != "pull --quiet docker.io/library/ubuntu:24.04" {
		t.Fatalf("pulls: %q", lines)
	}
	b, _ := AuthFile("docker", &kri.RegistryAuth{Server: "docker.io", Username: "u", Password: []byte("p")})
	if !strings.Contains(string(b), `"https://index.docker.io/v1/"`) {
		t.Fatalf("docker hub key: %s", b)
	}
	b, _ = AuthFile("podman", &kri.RegistryAuth{Server: "docker.io", Username: "u", Password: []byte("p")})
	if !strings.Contains(string(b), `"docker.io"`) {
		t.Fatalf("podman hub key: %s", b)
	}
}

// Start and init containers never pull on their own: every pull is the agent's, with its
// credential. Create pulls (anonymously) only an image that isn't there yet.
func TestNoPullsBehindTheAgentsBack(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	ref := "ghcr.io/acme/api:v1"
	f.images[ref] = true // the agent pulled it
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: ref}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RunInit(ctx, silo, kri.InitStep{Name: "x", Run: "true"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.cmds {
		if strings.HasPrefix(c, "docker pull") {
			t.Errorf("pulled by itself: %s", c)
		}
		if strings.HasPrefix(c, "docker run") && !strings.Contains(c, "kevaso-pause") && !strings.Contains(c, "--pull never") {
			t.Errorf("a run that may pull: %s", c)
		}
	}
}

func TestPickDigest(t *testing.T) {
	d1, d2 := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	for _, tc := range []struct {
		ref  string
		rds  []string
		want string
	}{
		{"nginx:1.27", []string{"nginx@" + d1}, d1},                                     // docker: Hub names short
		{"docker.io/library/nginx:1.27", []string{"docker.io/library/nginx@" + d1}, d1}, // podman: long
		{"ghcr.io/a/b:v1", []string{"ghcr.io/a/c@" + d1, "ghcr.io/a/b@" + d2}, d2},      // its own repository
		{"ghcr.io/a/b:v1", []string{"mirror.example.com/a/b@" + d1}, d1},                // else the first
		{"ghcr.io/a/b:v1", nil, ""},
	} {
		if got := PickDigest(tc.ref, tc.rds); got != tc.want {
			t.Errorf("%s %v: %q, want %q", tc.ref, tc.rds, got, tc.want)
		}
	}
}
