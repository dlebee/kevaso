package kvoplugin_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	b64 "encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/internal/kvoplugin"
	"kevaso.com/core/internal/kvoplugin/plugintest"
)

var (
	macARM = kvoplugin.Platform{OS: "darwin", Arch: "arm64"}
	linux  = kvoplugin.Platform{OS: "linux", Arch: "amd64"}
	win    = kvoplugin.Platform{OS: "windows", Arch: "amd64"}
)

func manager(t *testing.T, pub *plugintest.Publisher, pl kvoplugin.Platform) *kvoplugin.Manager {
	t.Helper()
	return &kvoplugin.Manager{Root: t.TempDir(), Platform: pl, DefaultURL: pub.URL(), DefaultKey: pub.PublicKey(),
		Reserved: func(n string) bool { return n == "get" }}
}

func TestVerifyIndex(t *testing.T) {
	pub := plugintest.New(t, "kevaso")
	pub.Add("hello", "v1.0.0", linux, kvoplugin.KindBinary, "", []byte("#!/bin/sh\n"))
	pub.Publish()
	doc, sig := pub.Signed()
	key := pub.Key.Public().(ed25519.PublicKey)
	ix, err := kvoplugin.Verify(doc, sig, key)
	if err != nil || len(ix.Plugins) != 1 {
		t.Fatalf("good index: %v", err)
	}

	tampered := bytes.Replace(doc, []byte(`"hello"`), []byte(`"hellp"`), 1)
	if _, err := kvoplugin.Verify(tampered, sig, key); err == nil {
		t.Error("tampered index accepted")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := kvoplugin.Verify(doc, sig, other); err == nil {
		t.Error("index accepted with the wrong key")
	}
	if _, err := kvoplugin.Verify(doc, []byte("bm90IGEgc2ln\n"), key); err == nil {
		t.Error("garbage signature accepted")
	}
	// A signature over the bare bytes (no context prefix), as kvoadm signs binaries, doesn't count.
	raw := ed25519.Sign(pub.Key, doc)
	if _, err := kvoplugin.Verify(doc, []byte(b64.StdEncoding.EncodeToString(raw)), key); err == nil {
		t.Error("a signature without the index context accepted")
	}
}

func TestIndexValidation(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := priv.Public().(ed25519.PublicKey)
	good := `{"apiVersion":"kevaso.com/plugin-index/v1","name":"x","generated":"2026-11-13T00:00:00Z","plugins":[{"name":"p","versions":[{"version":"v1.0.0","platforms":[%s]}]}]}`
	art := `{"os":"darwin","arch":"arm64","url":"a","sha256":"` + strings.Repeat("a", 64) + `","kind":%s}`
	for name, platform := range map[string]string{
		"unknown kind":          strings.Replace(art, "%s", `"exe"`, 1),
		"archive without entry": strings.Replace(art, "%s", `"tar.gz"`, 1),
		"entry escapes":         strings.Replace(art, "%s", `"zip","entry":"../x"`, 1),
		"binary with entry":     strings.Replace(art, "%s", `"binary","entry":"x"`, 1),
		"bad hash":              strings.Replace(strings.Replace(art, "%s", `"binary"`, 1), strings.Repeat("a", 64), "abc", 1),
		"unknown os":            strings.Replace(strings.Replace(art, "%s", `"binary"`, 1), "darwin", "plan9", 1),
	} {
		doc := []byte(strings.Replace(good, "%s", platform, 1))
		if _, err := kvoplugin.Verify(doc, kvoplugin.Sign(priv, doc), key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := []byte(strings.Replace(good, "%s", strings.Replace(art, "%s", `"tar.gz","entry":"A.app/Contents/MacOS/A"`, 1), 1))
	if _, err := kvoplugin.Verify(ok, kvoplugin.Sign(priv, ok), key); err != nil {
		t.Errorf("good: %v", err)
	}
}

func tgz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, b := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(b))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func TestInstallUpgradeRemove(t *testing.T) {
	ctx := context.Background()
	pub := plugintest.New(t, "kevaso")
	pub.Add("hello", "v1.0.0", linux, kvoplugin.KindBinary, "", []byte("one"))
	pub.Add("hello", "v1.0.0", win, kvoplugin.KindBinary, "", []byte("one.exe"))
	pub.Publish()
	m := manager(t, pub, linux)

	p, err := m.Install(ctx, "hello", "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != "v1.0.0" || p.Entry != "kvo-hello" || p.Ref() != "hello" {
		t.Fatalf("manifest: %+v", p)
	}
	if b, _ := os.ReadFile(p.Program()); string(b) != "one" {
		t.Fatalf("program: %q", b)
	}
	if !strings.HasPrefix(p.Dir, m.Root) {
		t.Fatalf("installed outside the root: %s", p.Dir)
	}

	// windows gets kvo-hello.exe
	mw := manager(t, pub, win)
	if p, err := mw.Install(ctx, "hello", ""); err != nil || p.Entry != "kvo-hello.exe" {
		t.Fatalf("windows: %+v %v", p, err)
	}

	// A new release, and a pre-release that upgrade skips.
	pub.Add("hello", "v1.1.0", linux, kvoplugin.KindBinary, "", []byte("two"))
	pub.Add("hello", "v2.0.0-rc.1", linux, kvoplugin.KindBinary, "", []byte("rc"))
	pub.Publish()
	ups, err := m.Upgrade(ctx, "")
	if err != nil || len(ups) != 1 || ups[0].From != "v1.0.0" || ups[0].To != "v1.1.0" {
		t.Fatalf("upgrade: %+v %v", ups, err)
	}
	if b, _ := os.ReadFile(p.Program()); string(b) != "two" {
		t.Fatalf("after upgrade: %q", b)
	}
	if ups, err := m.Upgrade(ctx, "hello"); err != nil || ups[0].From != ups[0].To {
		t.Fatalf("second upgrade: %+v %v", ups, err)
	}
	// A pre-release on purpose.
	if p, err := m.Install(ctx, "hello@v2.0.0-rc.1", ""); err == nil {
		t.Fatalf("@ is the CLI's job, not the manager's: %+v", p)
	}
	if p, err := m.Install(ctx, "hello", "v2.0.0-rc.1"); err != nil || p.Version != "v2.0.0-rc.1" {
		t.Fatalf("pre-release: %+v %v", p, err)
	}
	if list, _ := m.List(); len(list) != 1 || list[0].Version != "v2.0.0-rc.1" {
		t.Fatalf("list: %+v", list)
	}
	if _, err := m.Remove("hello"); err != nil {
		t.Fatal(err)
	}
	if list, _ := m.List(); len(list) != 0 {
		t.Fatalf("after remove: %+v", list)
	}
	if _, err := os.Stat(p.Dir); !os.IsNotExist(err) {
		t.Fatalf("folder left: %v", err)
	}
	if ents, _ := os.ReadDir(filepath.Join(m.Root, "tmp")); len(ents) != 0 {
		t.Fatalf("staging left behind: %v", ents)
	}
}

func TestInstallRefuses(t *testing.T) {
	ctx := context.Background()
	pub := plugintest.New(t, "kevaso")
	pub.Add("hello", "v1.0.0", linux, kvoplugin.KindBinary, "", []byte("one"))
	pub.Add("get", "v1.0.0", linux, kvoplugin.KindBinary, "", []byte("shadow"))
	pub.Add("app", "v1.0.0", macARM, kvoplugin.KindTarGz, "A.app/Contents/MacOS/A", tgz(t, map[string]string{"A.app/Contents/Info.plist": "x"}))
	pub.Publish()

	// No build for this platform: said plainly, naming what exists.
	m := manager(t, pub, macARM)
	_, err := m.Install(ctx, "hello", "")
	if !errors.Is(err, kvoplugin.ErrNoBuild) || !strings.Contains(err.Error(), "darwin/arm64") || !strings.Contains(err.Error(), "linux/amd64") {
		t.Errorf("wrong platform: %v", err)
	}
	// The archive's entry point isn't in it.
	if _, err := m.Install(ctx, "app", ""); err == nil || !strings.Contains(err.Error(), "entry point") {
		t.Errorf("missing entry: %v", err)
	}
	// kvo's own command names.
	ml := manager(t, pub, linux)
	if _, err := ml.Install(ctx, "get", ""); err == nil || !strings.Contains(err.Error(), "kvo's own commands") {
		t.Errorf("reserved: %v", err)
	}
	if _, err := ml.Install(ctx, "hello", "v9.9.9"); err == nil || !strings.Contains(err.Error(), "no version") {
		t.Errorf("missing version: %v", err)
	}
	if _, err := ml.Install(ctx, "nothere", ""); err == nil {
		t.Error("a plugin not in the index installed")
	}

	// A tampered artifact: the hash doesn't match, nothing is installed or unpacked.
	pub.Tamper = func(path string, b []byte) []byte {
		if strings.HasPrefix(path, "/files/") {
			b[0] ^= 1 // same size, other bytes
		}
		return b
	}
	if _, err := ml.Install(ctx, "hello", ""); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Errorf("tampered artifact: %v", err)
	}
	// A tampered index.
	pub.Tamper = func(path string, b []byte) []byte {
		if path == "/index.json" {
			return bytes.Replace(b, []byte("v1.0.0"), []byte("v1.0.1"), 1)
		}
		return b
	}
	if _, err := ml.Install(ctx, "hello", ""); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("tampered index: %v", err)
	}
	pub.Tamper = nil
	if list, _ := ml.List(); len(list) != 0 {
		t.Fatalf("something installed: %+v", list)
	}

	// The wrong key.
	other := plugintest.New(t, "kevaso")
	mk := manager(t, pub, linux)
	mk.DefaultKey = other.PublicKey()
	if _, err := mk.Install(ctx, "hello", ""); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("wrong key: %v", err)
	}
	// No key built in yet.
	mk.DefaultKey = ""
	if _, err := mk.Install(ctx, "hello", ""); !errors.Is(err, kvoplugin.ErrNotPublished) {
		t.Errorf("no key: %v", err)
	}
	// Plain http to another machine.
	mk.DefaultKey, mk.DefaultURL = pub.PublicKey(), "http://plugins.example.com/index.json"
	if _, err := mk.Install(ctx, "hello", ""); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("plain http: %v", err)
	}
}

func TestRollbackRefused(t *testing.T) {
	ctx := context.Background()
	pub := plugintest.New(t, "kevaso")
	pub.Add("hello", "v1.0.0", linux, kvoplugin.KindBinary, "", []byte("one"))
	pub.Publish()
	oldDoc, oldSig := pub.Signed()
	pub.Add("hello", "v1.0.1", linux, kvoplugin.KindBinary, "", []byte("fix"))
	pub.Publish()
	m := manager(t, pub, linux)
	if p, err := m.Install(ctx, "hello", ""); err != nil || p.Version != "v1.0.1" {
		t.Fatalf("install: %+v %v", p, err)
	}
	// A mirror serves the older, validly signed index.
	pub.Serve(oldDoc, oldSig)
	if _, err := m.Install(ctx, "hello", ""); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Errorf("rollback: %v", err)
	}
}

func TestThirdPartyIndex(t *testing.T) {
	ctx := context.Background()
	kevaso := plugintest.New(t, "kevaso")
	acme := plugintest.New(t, "acme")
	acme.Add("foo", "v0.1.0", linux, kvoplugin.KindBinary, "", []byte("foo"))
	acme.Publish()
	m := manager(t, kevaso, linux)

	if _, err := m.AddIndex(ctx, acme.URL(), kevaso.PublicKey(), ""); err == nil {
		t.Error("index added with a key that doesn't sign it")
	}
	if _, err := m.AddIndex(ctx, acme.URL(), acme.PublicKey(), "kevaso"); err == nil {
		t.Error("index took the built-in index's name")
	}
	ref, err := m.AddIndex(ctx, acme.URL(), acme.PublicKey(), "")
	if err != nil || ref.Name != "acme" {
		t.Fatalf("add: %+v %v", ref, err)
	}
	if _, err := m.Install(ctx, "foo", ""); err == nil {
		t.Error("foo installed from the built-in index, which doesn't have it")
	}
	p, err := m.Install(ctx, "acme/foo", "")
	if err != nil || p.Ref() != "acme/foo" {
		t.Fatalf("acme/foo: %+v %v", p, err)
	}
	found, errs := m.Search(ctx, "foo")
	if len(errs) != 0 || len(found) != 1 || found[0].Ref != "acme/foo" || found[0].Installed != "v0.1.0" {
		t.Fatalf("search: %+v %v", found, errs)
	}
	if err := m.RemoveIndex("acme"); err == nil {
		t.Error("index removed with a plugin from it installed")
	}
	if _, err := m.Remove("acme/foo"); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveIndex("acme"); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveIndex("kevaso"); err == nil {
		t.Error("built-in index removed")
	}
}

func TestEnvCarriesNoCredentials(t *testing.T) {
	p := kvoplugin.Manifest{Name: "panes", Index: "kevaso", Version: "v1.0.0", Dir: "/p"}
	env := kvoplugin.Env([]string{"HOME=/h", "KVO_PLUGIN_SERVER=https://spoofed", "KVO_PLUGIN_EXTRA=x"}, p,
		kvoplugin.Session{Context: "work", Server: "https://cp:6443", CAFile: "/ca.pem", Namespace: "team", Kvo: "/bin/kvo"})
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := got[k]; dup {
			t.Errorf("%s set twice", k)
		}
		got[k] = v
	}
	if got["KVO_PLUGIN_SERVER"] != "https://cp:6443" || got["KVO_PLUGIN_NAME"] != "panes" || got["KVO_PLUGIN_CONTEXT"] != "work" || got["HOME"] != "/h" {
		t.Fatalf("env: %v", got)
	}
	if _, ok := got["KVO_PLUGIN_EXTRA"]; ok {
		t.Error("a parent's KVO_PLUGIN_* passed through")
	}
}
