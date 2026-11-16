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
// unreadable is set when the file is there and can't be read: that is not an empty record.
type appliedLog struct {
	mu         sync.Mutex
	loaded     bool
	unreadable error
	path       string
	entries    map[string]appliedEntry
}

func (a *Agent) appliedFile() string {
	if p := a.deletesFile(); p != "" {
		return filepath.Join(filepath.Dir(p), AppliedFile)
	}
	return ""
}

// appliedLocked reads the file once. A file that isn't there is an empty record (nothing has been
// applied here). A file that can't be read is not: the caller refuses a replayed reset until it
// can (K-127). The next look reads it again.
func (a *Agent) appliedLocked() *appliedLog {
	l := &a.applied
	if l.loaded {
		return l
	}
	l.path, l.entries, l.unreadable = a.appliedFile(), map[string]appliedEntry{}, nil
	if l.path == "" {
		l.loaded = true
		return l
	}
	b, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		l.loaded = true
		return l
	}
	var list []appliedEntry
	if err == nil {
		err = json.Unmarshal(b, &list)
	}
	if err != nil {
		l.unreadable = err
		a.log("applied resets %s: %v: a reset or image the store says is due is not applied while the record can't be read", l.path, err)
		return l
	}
	l.loaded = true
	for _, e := range list {
		l.entries[e.UID] = e
	}
	return l
}

// alreadyApplied says whether this host recorded reset and image as the last applied to silo uid.
// An unreadable record is not empty: err is why, and a replayed reset must not be applied.
func (a *Agent) alreadyApplied(uid, reset, image string) (bool, error) {
	a.applied.mu.Lock()
	defer a.applied.mu.Unlock()
	l := a.appliedLocked()
	if l.unreadable != nil {
		return false, l.unreadable
	}
	e, ok := l.entries[uid]
	return ok && e.Reset == reset && e.Image == image, nil
}

// recordApplied records reset and image as applied to silo uid's disk here, synced to disk before
// the store is told (a crash in between leaves the record: the replayed request wipes nothing).
func (a *Agent) recordApplied(uid, reset, image string) {
	a.applied.mu.Lock()
	defer a.applied.mu.Unlock()
	l := a.appliedLocked()
	if l.unreadable != nil {
		a.log("applied resets %s: %v: %s is not recorded over a file that can't be read", l.path, l.unreadable, uid)
		return
	}
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
	if l.unreadable != nil || l.entries == nil {
		return // a file that can't be read is left as it is
	}
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
