package worker

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// The last state (K-062): what the worker's network last saw of the control plane's state, kept
// on disk so a kevasod that starts while the control plane is away comes up from it (its rules,
// its DNS listeners, its egress gate) instead of waiting. Every kind the network caches but
// secrets: no secret value is written to disk. It is the start of keeping a worker's whole last
// desired state (K-073, the owner's question): the agent's kinds would go in the same file.

// LastStateFile is the file's name in the worker's data directory.
const LastStateFile = "last-state.json"

// saveLastState writes st (every kept cache's list, taken once each has listed: never a seed,
// only what was seen) to path atomically and durably.
func saveLastState(path string, st map[string][]meta.Object) error {
	raw := map[string][]json.RawMessage{}
	for kind, objs := range st {
		items := []json.RawMessage{}
		for _, o := range objs {
			b, err := json.Marshal(o)
			if err != nil {
				return err
			}
			items = append(items, b)
		}
		raw[kind] = items
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return writeDurably(path, b)
}

// writeDurably writes b to path: a temporary file, flushed to the disk, renamed over path, the
// folder flushed too, so a power cut leaves the old file or the new one, never a short one.
func writeDurably(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// readLastState reads the last state at path for kinds: false when there is none, or when it
// isn't whole (K-122): a kind missing or null (a file cut short by a power cut, {} , one from a
// build that kept fewer kinds), or an object that doesn't decode. Such a file is no last state:
// seeding a kind from it as empty would install a view that closes every running silo's ports.
func readLastState(path string, kinds []string) (map[string][]meta.Object, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var st map[string][]json.RawMessage
	if json.Unmarshal(b, &st) != nil {
		return nil, false
	}
	out := map[string][]meta.Object{}
	for _, kind := range kinds {
		raws, ok := st[kind]
		if !ok || raws == nil {
			return nil, false
		}
		objs := []meta.Object{}
		for _, raw := range raws {
			o, _, err := v1.Decode(raw)
			if err != nil {
				return nil, false
			}
			objs = append(objs, o)
		}
		out[kind] = objs
	}
	return out, true
}

// seedLastState seeds the caches from path, kind by kind, and returns what it seeded; false, and
// nothing seeded, when there's no whole last state (a first start: wait for the control plane).
func seedLastState(path string, infs ...*informer.Informer) (map[string][]meta.Object, bool) {
	var kinds []string
	for _, inf := range infs {
		kinds = append(kinds, inf.Kind())
	}
	st, ok := readLastState(path, kinds)
	if !ok {
		return nil, false
	}
	for _, inf := range infs {
		inf.Seed(st[inf.Kind()])
	}
	return st, true
}

// SubnetFile keeps, in the worker's data directory, the silo subnet the control plane gave it
// (on the mesh): a start without the control plane uses it.
const SubnetFile = "silo-subnet"

func keepSubnet(dir string, p netip.Prefix) error {
	return os.WriteFile(filepath.Join(dir, SubnetFile), []byte(p.String()+"\n"), 0o600)
}

// keptStart says whether this worker can start without its control plane from what it kept:
// a last state, and on the mesh its silo subnet (returned).
func keptStart(dir string, mesh bool) (netip.Prefix, bool) {
	if dir == "" {
		return netip.Prefix{}, false
	}
	if _, err := os.Stat(filepath.Join(dir, LastStateFile)); err != nil {
		return netip.Prefix{}, false
	}
	if !mesh {
		return netip.Prefix{}, true
	}
	b, err := os.ReadFile(filepath.Join(dir, SubnetFile))
	if err != nil {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(string(b)))
	return p, err == nil
}
