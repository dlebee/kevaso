package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// SeenDeletesFile is where a worker keeps the silo deletes it saw whose copies here may not all
// be gone yet, next to its control-plane watermark (kevasod --data): a delete seen just before a
// restart, or a removal that was under way when kevasod stopped, is finished by the next run, and
// never turns into a kept copy (design §0.7: only a delete the host saw removes a silo's data,
// and this host saw it).
const SeenDeletesFile = "seen-deletes.json"

// seenDeleteFile is one entry: the silo the delete was of.
type seenDeleteFile struct {
	UID       string `json:"uid"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// deletesLog is the file of seen deletes; its zero value (no path) keeps them in memory only.
type deletesLog struct {
	mu      sync.Mutex
	path    string
	entries map[string]seenDeleteFile
}

// deletesFile is DeletesFile, or SeenDeletesFile beside the watermark's file ("": none kept).
func (a *Agent) deletesFile() string {
	if a.DeletesFile != "" {
		return a.DeletesFile
	}
	if w := a.watermark(); w != nil && w.path != "" {
		return filepath.Join(filepath.Dir(w.path), SeenDeletesFile)
	}
	return ""
}

// loadSeenDeletes reads the deletes an earlier run saw and hadn't finished removing: they count
// as seen in this run too (seenDeleted), so their copies here are removed.
func (a *Agent) loadSeenDeletes() {
	d := &a.deletes
	d.mu.Lock()
	defer d.mu.Unlock()
	d.path, d.entries = a.deletesFile(), map[string]seenDeleteFile{}
	if d.path == "" {
		return
	}
	b, err := os.ReadFile(d.path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var list []seenDeleteFile
	if err == nil {
		err = json.Unmarshal(b, &list)
	}
	if err != nil {
		// Unreadable: nothing in it counts. Its copies are kept, as for a delete never seen (the
		// safe side), and it is written anew from this run's deletes.
		a.log("seen deletes %s: %v: its copies are kept unless their delete is seen again", d.path, err)
		return
	}
	for _, e := range list {
		d.entries[e.UID] = e
		a.seenDeleted.Store(e.UID, struct{}{})
	}
	if len(list) > 0 {
		a.log("seen deletes %s: %d silo(s) deleted before this run whose copies here are removed now", d.path, len(list))
	}
}

// sawDelete records the delete of silo id as seen here (in memory, and, if keep, on disk, written
// and synced before the caller acts on it), and ends a start of it under way here: its init step or
// Start stops now, not at its claim's next renewal.
func (a *Agent) sawDelete(id kri.ID, keep bool) {
	a.seenDeleted.Store(id.UID, struct{}{})
	d := &a.deletes
	d.mu.Lock()
	if keep && d.path != "" {
		if _, ok := d.entries[id.UID]; !ok {
			d.entries[id.UID] = seenDeleteFile{UID: id.UID, Namespace: id.Namespace, Name: id.Name}
			if err := d.writeLocked(); err != nil {
				a.log("seen deletes %s: %v: the delete of %s is kept in memory only (a restart before its copy is removed keeps the copy)", d.path, err, id)
			}
		}
	}
	d.mu.Unlock()
	a.endStart(id.UID)
}

// mayHaveHere says whether this host may hold something of the silo a delete was of: placed or
// moving here as the delete had it, starting here, or listed by a runtime. Only those deletes are
// kept on disk (the watch sees every delete in the cluster).
func (a *Agent) mayHaveHere(ctx context.Context, s *v1.Silo) bool {
	if s.Status.Host == a.HostName || s.Status.MovingFrom == a.HostName {
		return true
	}
	if _, ok := a.claims.Load(s.UID); ok {
		return true
	}
	for _, rt := range a.Runtimes {
		ids, err := rt.List(ctx)
		if err != nil {
			return true // can't say: kept
		}
		for _, id := range ids {
			if id.UID == s.UID {
				return true
			}
		}
	}
	return false
}

// forgetDelete drops uid from the file once nothing of it is left here (it stays seen in memory
// for the rest of this run).
func (a *Agent) forgetDelete(uid string) {
	d := &a.deletes
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.entries[uid]; !ok || d.path == "" {
		return
	}
	delete(d.entries, uid)
	if err := d.writeLocked(); err != nil {
		a.log("seen deletes %s: %v", d.path, err)
	}
}

// pruneDeletes drops the entries no runtime lists any more (their removal finished before a
// restart could record it). Only when every runtime answered.
func (a *Agent) pruneDeletes(ctx context.Context) {
	have := map[string]bool{}
	for _, rt := range a.Runtimes {
		ids, err := rt.List(ctx)
		if err != nil {
			return
		}
		for _, id := range ids {
			have[id.UID] = true
		}
	}
	d := &a.deletes
	d.mu.Lock()
	defer d.mu.Unlock()
	changed := false
	for uid := range d.entries {
		if !have[uid] {
			delete(d.entries, uid)
			changed = true
		}
	}
	if changed && d.path != "" {
		if err := d.writeLocked(); err != nil {
			a.log("seen deletes %s: %v", d.path, err)
		}
	}
}

// writeLocked writes the file atomically: a temporary file, synced, renamed over it, the folder
// synced.
func (d *deletesLog) writeLocked() error {
	list := make([]seenDeleteFile, 0, len(d.entries))
	for _, e := range d.entries {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].UID < list[j].UID })
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	dir := filepath.Dir(d.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := d.path + ".tmp"
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
	if err := os.Rename(tmp, d.path); err != nil {
		return err
	}
	df, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = df.Close() }()
	return df.Sync()
}
