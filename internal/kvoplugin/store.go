package kvoplugin

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/internal/upgrade"
)

// DefaultRoot is where a person's plugins live, in their own folder (no admin rights):
// $KVO_PLUGINS_DIR, else ~/Library/Application Support/Kevaso/kvo/plugins on macOS,
// %LOCALAPPDATA%\Kevaso\kvo\plugins on Windows, $XDG_DATA_HOME/kevaso/kvo/plugins
// (~/.local/share/…) elsewhere.
func DefaultRoot() (string, error) {
	if d := os.Getenv("KVO_PLUGINS_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Kevaso", "kvo", "plugins"), nil
	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			base = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(base, "Kevaso", "kvo", "plugins"), nil
	}
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "kevaso", "kvo", "plugins"), nil
}

// ErrNotPublished: the built-in index has no key yet.
var ErrNotPublished = errors.New("the Kevaso plugin index isn't published yet (no key built into this kvo); add an index with kvo plugin index add")

// Manager installs, lists and removes one person's plugins.
type Manager struct {
	Root     string
	Platform Platform
	HTTP     *http.Client
	// The built-in index: DefaultIndexURL and DefaultIndexKey unless set (tests, a local index).
	DefaultURL, DefaultKey string
	// Reserved names can't be installed (kvo's own commands).
	Reserved func(string) bool
	Now      func() time.Time
}

// New is a Manager for this machine and user. $KVO_PLUGIN_INDEX and $KVO_PLUGIN_INDEX_KEY replace
// the built-in index (for a local or staging index; ADR 0008).
func New() (*Manager, error) {
	root, err := DefaultRoot()
	if err != nil {
		return nil, err
	}
	m := &Manager{Root: root, Platform: Host(), DefaultURL: DefaultIndexURL, DefaultKey: DefaultIndexKey}
	if u := os.Getenv("KVO_PLUGIN_INDEX"); u != "" {
		m.DefaultURL, m.DefaultKey = u, os.Getenv("KVO_PLUGIN_INDEX_KEY")
	}
	return m, nil
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

// IndexRef is an index kvo trusts: where it is, the key it must be signed with, the name its
// plugins are shown under, and the newest generated time seen (an older index is a rollback).
type IndexRef struct {
	Name string    `json:"name"`
	URL  string    `json:"url"`
	Key  string    `json:"key"`
	Seen time.Time `json:"seen,omitzero"`
}

type indexFile struct {
	Indexes     []IndexRef           `json:"indexes"`
	DefaultSeen map[string]time.Time `json:"defaultSeen,omitempty"` // per default URL
}

func (m *Manager) indexPath() string { return filepath.Join(m.Root, "indexes.json") }

func (m *Manager) loadIndexes() (indexFile, error) {
	var f indexFile
	b, err := os.ReadFile(m.indexPath())
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	return f, json.Unmarshal(b, &f)
}

func (m *Manager) saveIndexes(f indexFile) error {
	if err := os.MkdirAll(m.Root, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.indexPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.indexPath())
}

// Indexes lists the built-in index first, then the ones added.
func (m *Manager) Indexes() ([]IndexRef, error) {
	f, err := m.loadIndexes()
	if err != nil {
		return nil, err
	}
	out := []IndexRef{{Name: DefaultIndexName, URL: m.DefaultURL, Key: m.DefaultKey, Seen: f.DefaultSeen[m.DefaultURL]}}
	return append(out, f.Indexes...), nil
}

func (m *Manager) indexRef(name string) (IndexRef, error) {
	ixs, err := m.Indexes()
	if err != nil {
		return IndexRef{}, err
	}
	for _, ix := range ixs {
		if ix.Name == name {
			return ix, nil
		}
	}
	return IndexRef{}, fmt.Errorf("no plugin index named %s (kvo plugin index list)", name)
}

// allowedURL: https anywhere, plain http only to this machine (a local index, tests).
func allowedURL(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if h == "localhost" {
			return nil
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("%s: plugins come over https (plain http only from this machine)", u.Redacted())
}

func (m *Manager) get(ctx context.Context, u *url.URL, limit int64, w io.Writer) error {
	if err := allowedURL(u); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := m.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", u.Redacted(), resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("%s: more than %d bytes", u.Redacted(), limit)
	}
	return nil
}

const maxIndex = 8 << 20

// fetched is a verified index and where it came from (artifact URLs are relative to it).
type fetched struct {
	ref  IndexRef
	base *url.URL
	ix   *Index
}

// fetch downloads an index and its signature (URL + ".sig"), verifies it with ref's key, refuses a
// rollback, and remembers the newest generated time.
func (m *Manager) fetch(ctx context.Context, ref IndexRef) (*fetched, error) {
	if ref.Key == "" {
		if ref.Name == DefaultIndexName {
			return nil, ErrNotPublished
		}
		return nil, fmt.Errorf("index %s has no key", ref.Name)
	}
	ix, u, err := m.download(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("index %s: %w", ref.Name, err)
	}
	if ix.Generated.Before(ref.Seen) {
		return nil, fmt.Errorf("index %s: generated %s, older than one already seen (%s): refusing a rollback",
			ref.Name, ix.Generated.Format(time.RFC3339), ref.Seen.Format(time.RFC3339))
	}
	if ix.Generated.After(ref.Seen) {
		if err := m.markSeen(ref, ix.Generated); err != nil {
			return nil, err
		}
		ref.Seen = ix.Generated
	}
	return &fetched{ref: ref, base: u, ix: ix}, nil
}

func (m *Manager) markSeen(ref IndexRef, t time.Time) error {
	f, err := m.loadIndexes()
	if err != nil {
		return err
	}
	if ref.Name == DefaultIndexName {
		if f.DefaultSeen == nil {
			f.DefaultSeen = map[string]time.Time{}
		}
		f.DefaultSeen[ref.URL] = t
	} else {
		for i := range f.Indexes {
			if f.Indexes[i].Name == ref.Name {
				f.Indexes[i].Seen = t
			}
		}
	}
	return m.saveIndexes(f)
}

// AddIndex trusts a third party's index: it must verify with key now. name "" takes the one the
// index suggests.
func (m *Manager) AddIndex(ctx context.Context, rawURL, key, name string) (IndexRef, error) {
	if _, err := ParseKey(key); err != nil {
		return IndexRef{}, err
	}
	ref := IndexRef{URL: rawURL, Key: key, Name: "(new)"}
	got, _, err := m.download(ctx, ref)
	if err != nil {
		return IndexRef{}, err
	}
	if name == "" {
		name = got.Name
	}
	if !ValidName(name) || name == DefaultIndexName {
		return IndexRef{}, fmt.Errorf("index name %q: pick another with --name (lower case, not %s)", name, DefaultIndexName)
	}
	f, err := m.loadIndexes()
	if err != nil {
		return IndexRef{}, err
	}
	for _, ix := range f.Indexes {
		if ix.Name == name {
			return IndexRef{}, fmt.Errorf("an index named %s is already added", name)
		}
	}
	ref = IndexRef{Name: name, URL: rawURL, Key: key, Seen: got.Generated}
	f.Indexes = append(f.Indexes, ref)
	return ref, m.saveIndexes(f)
}

// download gets an index and its signature (URL + ".sig") and verifies it with ref's key.
func (m *Manager) download(ctx context.Context, ref IndexRef) (*Index, *url.URL, error) {
	key, err := ParseKey(ref.Key)
	if err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(ref.URL)
	if err != nil {
		return nil, nil, err
	}
	var doc, sig strings.Builder
	if err := m.get(ctx, u, maxIndex, &doc); err != nil {
		return nil, nil, err
	}
	su := *u
	su.Path += ".sig"
	if err := m.get(ctx, &su, 4096, &sig); err != nil {
		return nil, nil, fmt.Errorf("signature: %w", err)
	}
	ix, err := Verify([]byte(doc.String()), []byte(sig.String()), key)
	return ix, u, err
}

// RemoveIndex stops trusting an index; its plugins must be removed first.
func (m *Manager) RemoveIndex(name string) error {
	if name == DefaultIndexName {
		return fmt.Errorf("%s is kvo's own index and stays", DefaultIndexName)
	}
	inst, err := m.List()
	if err != nil {
		return err
	}
	for _, p := range inst {
		if p.Index == name {
			return fmt.Errorf("%s is installed from it: kvo plugin remove %s first", p.Ref(), p.Ref())
		}
	}
	f, err := m.loadIndexes()
	if err != nil {
		return err
	}
	for i, ix := range f.Indexes {
		if ix.Name == name {
			f.Indexes = append(f.Indexes[:i], f.Indexes[i+1:]...)
			return m.saveIndexes(f)
		}
	}
	return fmt.Errorf("no plugin index named %s", name)
}

// ParseRef splits "panes" (the built-in index) or "acme/foo".
func ParseRef(ref string) (index, name string, err error) {
	index, name, ok := strings.Cut(ref, "/")
	if !ok {
		index, name = DefaultIndexName, ref
	}
	if !ValidName(index) || !ValidName(name) {
		return "", "", fmt.Errorf("%q isn't a plugin name (NAME, or INDEX/NAME for another index)", ref)
	}
	return index, name, nil
}

// Manifest says what was installed, from where.
type Manifest struct {
	Name        string    `json:"name"`
	Index       string    `json:"index"`
	IndexURL    string    `json:"indexURL"`
	Version     string    `json:"version"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	Kind        string    `json:"kind"`
	URL         string    `json:"url"`
	SHA256      string    `json:"sha256"`
	Entry       string    `json:"entry"` // under files/, forward slashes
	InstalledAt time.Time `json:"installedAt"`

	Dir string `json:"-"` // the plugin's folder
}

// Ref is how people name it: "panes", or "acme/foo".
func (p Manifest) Ref() string {
	if p.Index == DefaultIndexName {
		return p.Name
	}
	return p.Index + "/" + p.Name
}

// Program is the path to run.
func (p Manifest) Program() string {
	return filepath.Join(p.Dir, "files", filepath.FromSlash(p.Entry))
}

func (m *Manager) pluginDir(index, name string) string {
	return filepath.Join(m.Root, "installed", index, name)
}

// Installed reads one plugin's manifest; ok is false when it isn't installed.
func (m *Manager) Installed(ref string) (Manifest, bool, error) {
	index, name, err := ParseRef(ref)
	if err != nil {
		return Manifest{}, false, err
	}
	return m.readManifest(m.pluginDir(index, name))
}

func (m *Manager) readManifest(dir string) (Manifest, bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, false, nil
	}
	if err != nil {
		return Manifest{}, false, err
	}
	var p Manifest
	if err := json.Unmarshal(b, &p); err != nil {
		return Manifest{}, false, fmt.Errorf("%s: %w", dir, err)
	}
	if _, err := cleanRel(p.Entry); err != nil {
		return Manifest{}, false, fmt.Errorf("%s: %w", dir, err)
	}
	p.Dir = dir
	return p, true, nil
}

// List is every installed plugin, sorted by how people name them.
func (m *Manager) List() ([]Manifest, error) {
	dirs, err := filepath.Glob(filepath.Join(m.Root, "installed", "*", "*"))
	if err != nil {
		return nil, err
	}
	var out []Manifest
	for _, d := range dirs {
		p, ok, err := m.readManifest(d)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref() < out[j].Ref() })
	return out, nil
}

// Remove deletes an installed plugin's folder.
func (m *Manager) Remove(ref string) (Manifest, error) {
	p, ok, err := m.Installed(ref)
	if err != nil {
		return p, err
	}
	if !ok {
		return p, fmt.Errorf("%s isn't installed", ref)
	}
	return p, os.RemoveAll(p.Dir)
}

// Found is a plugin found in an index, for search.
type Found struct {
	Ref, Description, Latest string
	Available                bool   // has a build for this platform
	Installed                string // the installed version, if any
}

// Search lists plugins whose name or description contains term, from every index (an index that
// can't be read is reported in errs and skipped).
func (m *Manager) Search(ctx context.Context, term string) (found []Found, errs []error) {
	refs, err := m.Indexes()
	if err != nil {
		return nil, []error{err}
	}
	term = strings.ToLower(term)
	for _, ref := range refs {
		f, err := m.fetch(ctx, ref)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, p := range f.ix.Plugins {
			if term != "" && !strings.Contains(p.Name, term) && !strings.Contains(strings.ToLower(p.Description), term) {
				continue
			}
			r := Found{Ref: p.Name, Description: p.Description}
			if ref.Name != DefaultIndexName {
				r.Ref = ref.Name + "/" + p.Name
			}
			if v, _, err := p.Pick("", m.Platform); err == nil {
				r.Latest, r.Available = v.Version, true
			} else if vs := p.Sorted(); len(vs) > 0 {
				r.Latest = vs[0].Version
			}
			if inst, ok, _ := m.Installed(r.Ref); ok {
				r.Installed = inst.Version
			}
			found = append(found, r)
		}
	}
	return found, errs
}

// Install fetches, verifies and installs ref at version ("" = the newest release), replacing the
// version installed, if any.
func (m *Manager) Install(ctx context.Context, ref, version string) (Manifest, error) {
	index, name, err := ParseRef(ref)
	if err != nil {
		return Manifest{}, err
	}
	if m.Reserved != nil && m.Reserved(name) {
		return Manifest{}, fmt.Errorf("%s is one of kvo's own commands: no plugin can take its name", name)
	}
	iref, err := m.indexRef(index)
	if err != nil {
		return Manifest{}, err
	}
	f, err := m.fetch(ctx, iref)
	if err != nil {
		return Manifest{}, err
	}
	p, ok := f.ix.Find(name)
	if !ok {
		return Manifest{}, fmt.Errorf("no plugin %s in index %s (kvo plugin search)", name, index)
	}
	v, a, err := p.Pick(version, m.Platform)
	if err != nil {
		return Manifest{}, err
	}
	return m.install(ctx, f, name, v, a)
}

func (m *Manager) install(ctx context.Context, f *fetched, name string, v Version, a Artifact) (Manifest, error) {
	au, err := f.base.Parse(a.URL)
	if err != nil {
		return Manifest{}, err
	}
	tmpRoot := filepath.Join(m.Root, "tmp")
	if err := os.MkdirAll(tmpRoot, 0o700); err != nil {
		return Manifest{}, err
	}
	stage, err := os.MkdirTemp(tmpRoot, name+"-")
	if err != nil {
		return Manifest{}, err
	}
	defer func() { _ = os.RemoveAll(stage) }()

	// Download, hash, and only then look inside.
	dl := filepath.Join(stage, "download")
	out, err := os.OpenFile(dl, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { _ = out.Close() }()
	h := sha256.New()
	limit := int64(MaxDownload)
	if a.Size > 0 {
		limit = a.Size
	}
	if err := m.get(ctx, au, limit, io.MultiWriter(out, h)); err != nil {
		return Manifest{}, fmt.Errorf("%s %s: %w", name, v.Version, err)
	}
	if !HashOK(h.Sum(nil), a.SHA256) {
		return Manifest{}, fmt.Errorf("%s %s: the download's sha256 isn't the index's: refusing it", name, v.Version)
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return Manifest{}, err
	}

	dir := filepath.Join(stage, "plugin")
	files := filepath.Join(dir, "files")
	if err := os.MkdirAll(files, 0o755); err != nil {
		return Manifest{}, err
	}
	entry := a.Entry
	switch a.Kind {
	case KindBinary:
		entry = "kvo-" + name
		if a.OS == "windows" {
			entry += ".exe"
		}
		err = copyFile(out, filepath.Join(files, entry))
	case KindTarGz:
		err = UnpackTarGz(out, files)
	case KindZip:
		err = UnpackZip(out, files)
	}
	if err != nil {
		return Manifest{}, fmt.Errorf("%s %s: %w", name, v.Version, err)
	}
	prog := filepath.Join(files, filepath.FromSlash(entry))
	if fi, err := os.Lstat(prog); err != nil || !fi.Mode().IsRegular() {
		return Manifest{}, fmt.Errorf("%s %s: its entry point %s isn't a file in the archive", name, v.Version, entry)
	}
	if err := os.Chmod(prog, 0o755); err != nil {
		return Manifest{}, err
	}
	man := Manifest{Name: name, Index: f.ref.Name, IndexURL: f.ref.URL, Version: v.Version, OS: a.OS, Arch: a.Arch,
		Kind: a.Kind, URL: au.String(), SHA256: a.SHA256, Entry: entry, InstalledAt: m.now().UTC()}
	b, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644); err != nil {
		return Manifest{}, err
	}

	// Swap it in: the old version moves aside first, so a failure leaves one or the other.
	final := m.pluginDir(f.ref.Name, name)
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return Manifest{}, err
	}
	old := filepath.Join(stage, "old")
	hadOld := false
	if _, err := os.Lstat(final); err == nil {
		if err := os.Rename(final, old); err != nil {
			return Manifest{}, fmt.Errorf("replacing %s (is it running?): %w", name, err)
		}
		hadOld = true
	}
	if err := os.Rename(dir, final); err != nil {
		if hadOld {
			_ = os.Rename(old, final)
		}
		return Manifest{}, err
	}
	man.Dir = final
	return man, nil
}

func copyFile(src io.Reader, dst string) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, src); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Upgraded is one plugin's upgrade result.
type Upgraded struct {
	Ref, From, To string // To == From: already the newest
}

// Upgrade moves ref (or, with ref "", every installed plugin) to its index's newest release.
func (m *Manager) Upgrade(ctx context.Context, ref string) ([]Upgraded, error) {
	var targets []Manifest
	if ref != "" {
		p, ok, err := m.Installed(ref)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%s isn't installed (kvo plugin install %s)", ref, ref)
		}
		targets = []Manifest{p}
	} else {
		var err error
		if targets, err = m.List(); err != nil {
			return nil, err
		}
	}
	var out []Upgraded
	var errs []error
	for _, p := range targets {
		u, err := m.upgradeOne(ctx, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Ref(), err))
			continue
		}
		out = append(out, u)
	}
	return out, errors.Join(errs...)
}

func (m *Manager) upgradeOne(ctx context.Context, p Manifest) (Upgraded, error) {
	iref, err := m.indexRef(p.Index)
	if err != nil {
		return Upgraded{}, err
	}
	f, err := m.fetch(ctx, iref)
	if err != nil {
		return Upgraded{}, err
	}
	pl, ok := f.ix.Find(p.Name)
	if !ok {
		return Upgraded{}, fmt.Errorf("no longer in index %s", p.Index)
	}
	v, a, err := pl.Pick("", m.Platform)
	if err != nil {
		return Upgraded{}, err
	}
	cur, _ := upgrade.Parse(p.Version)
	next, _ := upgrade.Parse(v.Version)
	if next.Compare(cur) <= 0 {
		return Upgraded{Ref: p.Ref(), From: p.Version, To: p.Version}, nil
	}
	if _, err := m.install(ctx, f, p.Name, v, a); err != nil {
		return Upgraded{}, err
	}
	return Upgraded{Ref: p.Ref(), From: p.Version, To: v.Version}, nil
}
