package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// AppliedFile is where a worker keeps, per silo, the last reset and image it applied to the
// silo's disk here (K-110), next to its seen deletes. The store's status.image says the same, but
// a control plane restored from a backup taken between a reset's request and its completion says
// "still due": without this host's own record the root disk was wiped a second time, with all
// written to it since. A request this host recorded as applied wipes nothing.
const AppliedFile = "applied-resets.json"

// appliedEntry is one silo's last applied request: the reset (spec.reset, the request's own
// identity) and the image its disk was made from.
type appliedEntry struct {
	UID   string `json:"uid"`
	Reset string `json:"reset"`
	Image string `json:"image"`
}

// appliedLog is the file; its zero value (no path) keeps the entries in memory only.
type appliedLog struct {
	mu      sync.Mutex
	loaded  bool
	path    string
	entries map[string]appliedEntry
}

func (a *Agent) appliedFile() string {
	if p := a.deletesFile(); p != "" {
		return filepath.Join(filepath.Dir(p), AppliedFile)
	}
	return ""
}

// loadLocked reads the file once. An unreadable file counts as empty: a request is then applied
// as the store says (as before this record existed), and the file is written anew.
func (a *Agent) appliedLocked() *appliedLog {
	l := &a.applied
	if l.loaded {
		return l
	}
	l.loaded, l.path, l.entries = true, a.appliedFile(), map[string]appliedEntry{}
	if l.path == "" {
		return l
	}
	b, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return l
	}
	var list []appliedEntry
	if err == nil {
		err = json.Unmarshal(b, &list)
	}
	if err != nil {
		a.log("applied resets %s: %v: a reset or image the store says is due is applied", l.path, err)
		return l
	}
	for _, e := range list {
		l.entries[e.UID] = e
	}
	return l
}

// alreadyApplied says whether this host recorded reset and image as the last applied to silo uid.
func (a *Agent) alreadyApplied(uid, reset, image string) bool {
	a.applied.mu.Lock()
	defer a.applied.mu.Unlock()
	e, ok := a.appliedLocked().entries[uid]
	return ok && e.Reset == reset && e.Image == image
}

// recordApplied records reset and image as applied to silo uid's disk here, synced to disk before
// the store is told (a crash in between leaves the record: the replayed request wipes nothing).
func (a *Agent) recordApplied(uid, reset, image string) {
	a.applied.mu.Lock()
	defer a.applied.mu.Unlock()
	l := a.appliedLocked()
	l.entries[uid] = appliedEntry{UID: uid, Reset: reset, Image: image}
	if err := l.writeLocked(); err != nil {
		a.log("applied resets %s: %v (kept in memory only)", l.path, err)
	}
}

// forgetApplied drops silo uid's entry once its copy is removed here.
func (a *Agent) forgetApplied(uid string) {
	a.applied.mu.Lock()
	defer a.applied.mu.Unlock()
	l := a.appliedLocked()
	if _, ok := l.entries[uid]; !ok {
		return
	}
	delete(l.entries, uid)
	if err := l.writeLocked(); err != nil {
		a.log("applied resets %s: %v", l.path, err)
	}
}

func (l *appliedLog) writeLocked() error {
	if l.path == "" {
		return nil
	}
	list := make([]appliedEntry, 0, len(l.entries))
	for _, e := range l.entries {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].UID < list[j].UID })
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	d := deletesLog{path: l.path}
	return d.writeBytes(b)
}
