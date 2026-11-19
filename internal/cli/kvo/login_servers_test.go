package kvo

import (
	"context"
	"errors"
	"io"
	"testing"

	"kevaso.com/core/internal/kvoconfig"
)

func TestLoginSplitsACommaServerList(t *testing.T) {
	got := loginServers("https://a.example:6443, https://b.example:6443")
	if len(got) != 2 || got[0] != "https://a.example:6443" || got[1] != "https://b.example:6443" {
		t.Fatalf("servers = %#v", got)
	}
	var asked []string
	ca, server, err := fetchPinnedCA(context.Background(), got, "fp", func(_ context.Context, s, _ string) ([]byte, error) {
		asked = append(asked, s)
		if s == got[0] {
			return nil, errors.New("down")
		}
		return []byte("ca"), nil
	})
	if err != nil || server != got[1] || string(ca) != "ca" {
		t.Fatalf("ca %q from %q: %v", ca, server, err)
	}
	if len(asked) != 2 {
		t.Fatalf("asked %v, want both control planes", asked)
	}
}

func TestLoginRefusesPlainHTTP(t *testing.T) {
	for _, s := range []string{
		"http://cluster.example:6443",
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://[::1]:8080",
	} {
		if err := loginScheme(s); err == nil {
			t.Errorf("%s was accepted", s)
		}
	}
	if err := loginScheme("https://cluster.example:6443"); err != nil {
		t.Fatal(err)
	}
	called := false
	_, _, err := fetchPinnedCA(context.Background(), []string{"https://a.example:6443", "http://b.example:6443"}, "fp",
		func(context.Context, string, string) ([]byte, error) {
			called = true
			return []byte("ca"), nil
		})
	if err == nil || called {
		t.Fatalf("a list with plain http: err %v, fetch called %v", err, called)
	}
	cfg := kvoconfig.Config{CurrentContext: "c", Contexts: map[string]kvoconfig.Context{
		"c": {Server: "http://cluster.example:6443", Login: true},
	}}
	if err := loginCmd(context.Background(), t.TempDir(), cfg, opts{}, io.Discard, io.Discard); err == nil {
		t.Fatal("signing in again to a stored http server was accepted")
	}
}

func TestCanITreatsSiloSubresources(t *testing.T) {
	k, err := kindOf("silos")
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"ssh", "files", "open", "close", "move"} {
		res, name := canIResource(k.Plural, sub)
		if res != k.Plural+"/"+sub || name != "" {
			t.Fatalf("%s: resource %q name %q", sub, res, name)
		}
	}
	res, name := canIResource(k.Plural, "web")
	if res != k.Plural || name != "web" {
		t.Fatalf("a silo name became %q %q", res, name)
	}
}
