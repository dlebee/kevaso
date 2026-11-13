// Package kvoplugin is kvo's client plugins (design §10, "kvo plugins"; ADR 0008): programs a person
// runs next to kvo, installed per user from a signed index, one build per OS and CPU, and run as
// `kvo NAME …` with the current context and short-lived tokens, never long-lived credentials.
//
// It is not the hosts' provider plugins (sdk/kplugin, kvoadm plugin install) nor plugin operators.
package kvoplugin

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/internal/upgrade"
)

// The Kevaso plugin index. The key is the project's index-signing key (ADR 0008); until it exists,
// DefaultIndexKey is empty and kvo says the index isn't published yet.
const (
	DefaultIndexName = "kevaso"
	DefaultIndexURL  = "https://plugins.kevaso.com/v1/index.json"
	DefaultIndexKey  = ""
)

// APIVersion is the index document's version.
const APIVersion = "kevaso.com/plugin-index/v1"

// sigContext is prefixed to the index bytes before signing, so a signature over an index can never
// be taken for one over anything else made with the same kind of key (a kevasod binary, say).
const sigContext = "kevaso plugin index v1\n"

// Index is a signed document listing plugins.
type Index struct {
	APIVersion string    `json:"apiVersion"`
	Name       string    `json:"name"`      // the publisher's suggested name ("acme"); the user's choice wins
	Generated  time.Time `json:"generated"` // kvo refuses an index older than one it has seen
	Plugins    []Plugin  `json:"plugins"`
}

// Plugin is one name with its versions.
type Plugin struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Homepage    string    `json:"homepage,omitempty"`
	Versions    []Version `json:"versions"`
}

// Version is one release, with a build per platform.
type Version struct {
	Version   string     `json:"version"` // vMAJOR.MINOR.PATCH[-pre]
	Platforms []Artifact `json:"platforms"`
}

// Artifact kinds.
const (
	KindBinary = "binary" // the file is the program, saved as kvo-NAME (kvo-NAME.exe on Windows)
	KindTarGz  = "tar.gz" // an archive, unpacked; Entry names the program inside
	KindZip    = "zip"
)

// Artifact is what to fetch for one OS and CPU.
type Artifact struct {
	OS     string `json:"os"`   // GOOS: darwin, linux, windows
	Arch   string `json:"arch"` // GOARCH: arm64, amd64
	URL    string `json:"url"`  // absolute, or relative to the index's URL
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size,omitempty"`
	Kind   string `json:"kind"`
	Entry  string `json:"entry,omitempty"` // archives: the program, a relative path ("Kevaso Panes.app/Contents/MacOS/KevasoPanes")
}

// Platform is an OS and CPU, as Go names them.
type Platform struct{ OS, Arch string }

// Host is the platform kvo runs on.
func Host() Platform { return Platform{runtime.GOOS, runtime.GOARCH} }

func (p Platform) String() string { return p.OS + "/" + p.Arch }

var (
	nameRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	hexRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	osNames = map[string]bool{"darwin": true, "linux": true, "windows": true, "freebsd": true}
	archs   = map[string]bool{"amd64": true, "arm64": true}
)

// ValidName is a plugin or index name: lower case letters, digits and dashes, starting with a letter.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// ParseKey reads a public key written as ed25519:BASE64 (the raw 32 bytes).
func ParseKey(s string) (ed25519.PublicKey, error) {
	b64, ok := strings.CutPrefix(strings.TrimSpace(s), "ed25519:")
	if !ok {
		return nil, errors.New("a key is ed25519:BASE64")
	}
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, errors.New("a key is ed25519:BASE64 of 32 bytes")
	}
	return ed25519.PublicKey(k), nil
}

// FormatKey writes a public key as ParseKey reads it.
func FormatKey(k ed25519.PublicKey) string { return "ed25519:" + base64.StdEncoding.EncodeToString(k) }

// Sign signs an index document's exact bytes; the result is the .sig file's content.
func Sign(priv ed25519.PrivateKey, doc []byte) []byte {
	sig := ed25519.Sign(priv, append([]byte(sigContext), doc...))
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
}

// Verify checks the signature over doc, then parses and validates it. Nothing in doc is read before
// the signature holds.
func Verify(doc, sig []byte, key ed25519.PublicKey) (*Index, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("index signature: not a base64 ed25519 signature")
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(sigContext), doc...), raw) {
		return nil, errors.New("index signature doesn't match the index's key: refusing it")
	}
	var ix Index
	if err := json.Unmarshal(doc, &ix); err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	return &ix, ix.validate()
}

func (ix *Index) validate() error {
	if ix.APIVersion != APIVersion {
		return fmt.Errorf("index: apiVersion %q, want %q", ix.APIVersion, APIVersion)
	}
	if ix.Generated.IsZero() {
		return errors.New("index: no generated time")
	}
	seen := map[string]bool{}
	for _, p := range ix.Plugins {
		if !ValidName(p.Name) {
			return fmt.Errorf("index: bad plugin name %q", p.Name)
		}
		if seen[p.Name] {
			return fmt.Errorf("index: plugin %s listed twice", p.Name)
		}
		seen[p.Name] = true
		vs := map[string]bool{}
		for _, v := range p.Versions {
			if _, err := upgrade.Parse(v.Version); err != nil {
				return fmt.Errorf("index: %s: %w", p.Name, err)
			}
			if vs[v.Version] {
				return fmt.Errorf("index: %s %s listed twice", p.Name, v.Version)
			}
			vs[v.Version] = true
			plats := map[Platform]bool{}
			for _, a := range v.Platforms {
				if err := a.validate(); err != nil {
					return fmt.Errorf("index: %s %s: %w", p.Name, v.Version, err)
				}
				pl := Platform{a.OS, a.Arch}
				if plats[pl] {
					return fmt.Errorf("index: %s %s: %s listed twice", p.Name, v.Version, pl)
				}
				plats[pl] = true
			}
		}
	}
	return nil
}

func (a Artifact) validate() error {
	if !osNames[a.OS] || !archs[a.Arch] {
		return fmt.Errorf("unknown platform %s/%s", a.OS, a.Arch)
	}
	if a.URL == "" {
		return errors.New("an artifact needs a url")
	}
	if !hexRE.MatchString(a.SHA256) {
		return errors.New("an artifact's sha256 is 64 lower-case hex digits")
	}
	if a.Size < 0 || a.Size > MaxDownload {
		return fmt.Errorf("an artifact is at most %d bytes", MaxDownload)
	}
	switch a.Kind {
	case KindBinary:
		if a.Entry != "" {
			return errors.New("a binary has no entry")
		}
	case KindTarGz, KindZip:
		if _, err := cleanRel(a.Entry); err != nil {
			return fmt.Errorf("entry: %w", err)
		}
	default:
		return fmt.Errorf("unknown kind %q (binary, tar.gz or zip)", a.Kind)
	}
	return nil
}

// Find returns a plugin by name.
func (ix *Index) Find(name string) (*Plugin, bool) {
	for i := range ix.Plugins {
		if ix.Plugins[i].Name == name {
			return &ix.Plugins[i], true
		}
	}
	return nil, false
}

// Sorted returns the versions newest first.
func (p *Plugin) Sorted() []Version {
	vs := append([]Version(nil), p.Versions...)
	sort.SliceStable(vs, func(i, j int) bool {
		a, _ := upgrade.Parse(vs[i].Version)
		b, _ := upgrade.Parse(vs[j].Version)
		return a.Compare(b) > 0
	})
	return vs
}

// ErrNoBuild means the plugin (or version) has no build for this platform.
var ErrNoBuild = errors.New("no build")

// Pick chooses what to install: version "" is the newest release (not a pre-release) that has a
// build for pl, or a given version exactly.
func (p *Plugin) Pick(version string, pl Platform) (Version, Artifact, error) {
	var have []string
	for _, v := range p.Sorted() {
		pv, _ := upgrade.Parse(v.Version)
		if version != "" {
			want, err := upgrade.Parse(version)
			if err != nil {
				return Version{}, Artifact{}, err
			}
			if pv.Compare(want) != 0 {
				continue
			}
		} else if pv.Pre != "" {
			continue
		}
		for _, a := range v.Platforms {
			if a.OS == pl.OS && a.Arch == pl.Arch {
				return v, a, nil
			}
		}
		if version != "" || len(have) == 0 {
			for _, a := range v.Platforms {
				have = append(have, a.OS+"/"+a.Arch)
			}
		}
	}
	if version != "" && len(have) == 0 {
		if _, ok := p.version(version); !ok {
			return Version{}, Artifact{}, fmt.Errorf("%s has no version %s", p.Name, version)
		}
	}
	sort.Strings(have)
	built := "no platform yet"
	if len(have) > 0 {
		built = strings.Join(slicesCompact(have), ", ")
	}
	return Version{}, Artifact{}, fmt.Errorf("%s has %w for %s yet (built for: %s)", p.Name, ErrNoBuild, pl, built)
}

func (p *Plugin) version(v string) (Version, bool) {
	want, err := upgrade.Parse(v)
	if err != nil {
		return Version{}, false
	}
	for _, x := range p.Versions {
		if pv, _ := upgrade.Parse(x.Version); pv.Compare(want) == 0 {
			return x, true
		}
	}
	return Version{}, false
}

func slicesCompact(s []string) []string {
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// HashOK compares a computed digest with the index's (constant time is not needed: both are public).
func HashOK(sum []byte, want string) bool { return hex.EncodeToString(sum) == want }
