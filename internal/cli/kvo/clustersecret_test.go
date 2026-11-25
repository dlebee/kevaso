package kvo

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestClusterSecretUsage(t *testing.T) {
	t.Setenv("KVO_SERVER", "http://127.0.0.1:9")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "clustersecret"}, "create clustersecret needs a NAME"},
		{[]string{"create", "clustersecret", "bucket"}, "needs a value"},
		{[]string{"create", "clustersecret", "bucket", "--plugin", "juicefs"}, "unknown flag --plugin"},
		{[]string{"create", "clustersecret", "bucket", "--from-literal", "x", "--i-know"}, "comes from --from-file"},
		{[]string{"set"}, "usage: kvo set clustersecret"},
		{[]string{"set", "secret", "bucket"}, "usage: kvo set clustersecret"},
		{[]string{"set", "clustersecret", "bucket"}, "needs the new value"},
		{[]string{"get", "clustersecret", "--reveal"}, "--reveal works with one clustersecret"},
	} {
		var out, errb bytes.Buffer
		if code := Run(context.Background(), tc.args, strings.NewReader(""), &out, &errb); code == 0 || !strings.Contains(errb.String(), tc.want) {
			t.Errorf("%v: code %d, %q; want %q", tc.args, code, errb.String(), tc.want)
		}
	}
}

// create, set, get --reveal and delete speak the same messages as the secret commands, and the
// value goes in the body, not on the table.
func TestClusterSecretCommands(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("s3cret-bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var sent, stored v1.ClusterSecret
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/kevaso/v1/clustersecrets":
			if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
				t.Error(err)
			}
			stored = sent
			stored.Spec.Value = nil
			stored.Status.Version = 1
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(stored)
		case r.Method == http.MethodGet && r.URL.Path == "/apis/kevaso/v1/clustersecrets/bucket":
			out := stored
			out.Spec.Value = nil
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodPut && r.URL.Path == "/apis/kevaso/v1/clustersecrets/bucket":
			var next v1.ClusterSecret
			_ = json.NewDecoder(r.Body).Decode(&next)
			sent = next
			stored.Spec = next.Spec
			stored.Spec.Value = nil
			stored.Status.Version = 2
			_ = json.NewEncoder(w).Encode(stored)
		case r.Method == http.MethodGet && r.URL.Path == "/apis/kevaso/v1/clustersecrets/bucket/value":
			if r.URL.Query().Get("key") == "user" {
				_ = json.NewEncoder(w).Encode(client.SecretValue{Value: []byte("alice"), Version: 2})
				return
			}
			_ = json.NewEncoder(w).Encode(client.SecretValue{Data: map[string][]byte{v1.ValueKey: []byte("s3cret-bytes")}, Version: 2})
		case r.Method == http.MethodGet && r.URL.Path == "/apis/kevaso/v1/clustersecrets":
			item, _ := json.Marshal(stored)
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []json.RawMessage{item}, "metadata": map[string]string{"resourceVersion": "1"}})
		case r.Method == http.MethodDelete && r.URL.Path == "/apis/kevaso/v1/clustersecrets/bucket":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":200,"reason":"Deleted","message":"gone"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("KVO_SERVER", srv.URL)

	var out, errb bytes.Buffer
	args := []string{"create", "clustersecret", "bucket", "--description", "bucket key", "--from-file", path}
	if code := Run(context.Background(), args, strings.NewReader(""), &out, &errb); code != 0 || strings.TrimSpace(out.String()) != "clustersecret/bucket created (version 1)" {
		t.Fatalf("create: %d %q %q", code, out.String(), errb.String())
	}
	if string(sent.Spec.Value) != "s3cret-bytes" || sent.Spec.Description != "bucket key" {
		t.Fatalf("stored spec: %+v", sent.Spec)
	}
	if sent.Status.Version != 0 || sent.Status.ChangedAt != nil {
		t.Fatalf("create sent a status: %+v", sent.Status)
	}
	stored.ObjectMeta = meta.ObjectMeta{Name: "bucket", ResourceVersion: "3"}

	out.Reset()
	if code := Run(context.Background(), []string{"set", "clustersecret", "bucket", "--from-file", "-"}, strings.NewReader("next-bytes\n"), &out, &errb); code != 0 || strings.TrimSpace(out.String()) != "clustersecret/bucket: version 2" {
		t.Fatalf("set: %d %q %q", code, out.String(), errb.String())
	}
	if string(sent.Spec.Value) != "next-bytes" {
		t.Fatalf("rotated value: %q", sent.Spec.Value)
	}

	out.Reset()
	if code := Run(context.Background(), []string{"get", "clustersecret"}, strings.NewReader(""), &out, &errb); code != 0 || strings.Contains(out.String(), "s3cret") || strings.Contains(out.String(), "next-bytes") || !strings.Contains(out.String(), "bucket key") {
		t.Fatalf("get: %d %q %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := Run(context.Background(), []string{"get", "clustersecret", "bucket", "--reveal"}, strings.NewReader(""), &out, &errb); code != 0 || out.String() != "s3cret-bytes" {
		t.Fatalf("reveal: %d %q %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := Run(context.Background(), []string{"delete", "clustersecret", "bucket"}, strings.NewReader(""), &out, &errb); code != 0 || strings.TrimSpace(out.String()) != "clustersecret/bucket deleted" {
		t.Fatalf("delete: %d %q %q", code, out.String(), errb.String())
	}
}
