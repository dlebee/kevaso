// Package plugintest serves a signed kvo plugin index and its artifacts from a local HTTP server,
// for tests.
package plugintest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/internal/kvoplugin"
)

// Publisher is an index publisher: a key, a document, files, and a server.
type Publisher struct {
	Key    ed25519.PrivateKey
	Server *httptest.Server

	mu    sync.Mutex
	Index kvoplugin.Index
	files map[string][]byte
	// Tamper, if set, changes what is served at a path after signing (tests of a bad mirror).
	Tamper func(path string, b []byte) []byte
	doc    []byte
	sig    []byte
}

// New starts a publisher whose index suggests the name name.
func New(t testing.TB, name string) *Publisher {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &Publisher{Key: priv, files: map[string][]byte{},
		Index: kvoplugin.Index{APIVersion: kvoplugin.APIVersion, Name: name, Generated: time.Now().UTC().Truncate(time.Second)}}
	p.Server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.Server.Close)
	p.Publish()
	return p
}

// URL is the index's URL.
func (p *Publisher) URL() string { return p.Server.URL + "/index.json" }

// PublicKey is the key as kvo takes it.
func (p *Publisher) PublicKey() string {
	return kvoplugin.FormatKey(p.Key.Public().(ed25519.PublicKey))
}

// Add serves body as one build of name at version and lists it. kind is a kvoplugin.Kind*.
func (p *Publisher) Add(name, version string, pl kvoplugin.Platform, kind, entry string, body []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	path := fmt.Sprintf("/files/%s/%s/%s-%s", name, version, pl.OS, pl.Arch)
	p.files[path] = body
	sum := sha256.Sum256(body)
	a := kvoplugin.Artifact{OS: pl.OS, Arch: pl.Arch, URL: "files/" + path[len("/files/"):], SHA256: hex.EncodeToString(sum[:]),
		Size: int64(len(body)), Kind: kind, Entry: entry}
	var pg *kvoplugin.Plugin
	if f, ok := p.Index.Find(name); ok {
		pg = f
	} else {
		p.Index.Plugins = append(p.Index.Plugins, kvoplugin.Plugin{Name: name, Description: "the " + name + " plugin"})
		pg = &p.Index.Plugins[len(p.Index.Plugins)-1]
	}
	for i := range pg.Versions {
		if pg.Versions[i].Version == version {
			pg.Versions[i].Platforms = append(pg.Versions[i].Platforms, a)
			return
		}
	}
	pg.Versions = append(pg.Versions, kvoplugin.Version{Version: version, Platforms: []kvoplugin.Artifact{a}})
}

// Publish signs the current document (a second later than the last, like a real publisher).
func (p *Publisher) Publish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.doc != nil {
		p.Index.Generated = p.Index.Generated.Add(time.Second)
	}
	p.doc, _ = json.MarshalIndent(p.Index, "", "  ")
	p.sig = kvoplugin.Sign(p.Key, p.doc)
}

// Serve replaces what's served as the index and signature (for rollback tests).
func (p *Publisher) Serve(doc, sig []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.doc, p.sig = doc, sig
}

// Signed is what's served now.
func (p *Publisher) Signed() (doc, sig []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.doc, p.sig
}

func (p *Publisher) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	var b []byte
	switch r.URL.Path {
	case "/index.json":
		b = p.doc
	case "/index.json.sig":
		b = p.sig
	default:
		b = p.files[r.URL.Path]
	}
	tamper := p.Tamper
	p.mu.Unlock()
	if b == nil {
		http.NotFound(w, r)
		return
	}
	if tamper != nil {
		b = tamper(r.URL.Path, append([]byte(nil), b...))
	}
	_, _ = w.Write(b)
}
