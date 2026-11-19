package kvo

import (
	"context"
	"errors"
	"testing"
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
