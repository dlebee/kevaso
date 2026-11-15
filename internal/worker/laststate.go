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

// saveLastState writes every given cache that has listed (never a seed: only what was seen) to
// path atomically; nothing when one of them hasn't listed yet.
func saveLastState(path string, infs ...*informer.Informer) error {
	if !informer.AllSynced(infs...) {
		return nil
	}
	st := map[string][]json.RawMessage{}
	for _, inf := range infs {
		items := []json.RawMessage{}
		for _, o := range inf.List() {
			b, err := json.Marshal(o)
			if err != nil {
				return err
			}
			items = append(items, b)
		}
		st[inf.Kind()] = items
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// seedLastState seeds the caches from path, kind by kind; false when there's no last state (a
// first start: wait for the control plane).
func seedLastState(path string, infs ...*informer.Informer) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var st map[string][]json.RawMessage
	if json.Unmarshal(b, &st) != nil {
		return false
	}
	for _, inf := range infs {
		var objs []meta.Object
		for _, raw := range st[inf.Kind()] {
			if o, _, err := v1.Decode(raw); err == nil {
				objs = append(objs, o)
			}
		}
		inf.Seed(objs)
	}
	return true
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
