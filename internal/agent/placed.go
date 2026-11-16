package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// PlacedUnderFile is where a worker keeps, per silo, the history (Watermark.history) under which
// it last read that silo placed here, next to its seen deletes (K-126). The copy in memory is
// gone when kevasod restarts. A restart after a new history was saved would otherwise take the
// history at start (the new one) as the one the copy was placed under, and a handoff that is a
// restore's replay would remove the live root disk.
const PlacedUnderFile = "placed-under.json"

// historyNotRecorded is historyPlaced's answer for a copy with no record after a new history:
// not a history any control plane has, so the handoff compares unequal and is kept.
const historyNotRecorded = "no record"

// placedEntry is one silo's last placement here.
type placedEntry struct {
	UID     string `json:"uid"`
	History string `json:"history"`
}

// placedLog is the file; its zero value (no path) keeps the entries in memory only.
type placedLog struct {
	mu      sync.Mutex
	path    string
	entries map[string]placedEntry
}

func (a *Agent) placedFile() string {
	if p := a.deletesFile(); p != "" {
		return filepath.Join(filepath.Dir(p), PlacedUnderFile)
	}
	return ""
}

// loadPlacedUnder reads the placements an earlier run recorded into placedUnder. A copy with no
// entry, once a saved placement is from another history (or the file can't be read), was not
// placed here under the history trusted now.
func (a *Agent) loadPlacedUnder() {
	p := &a.placed
	p.mu.Lock()
	defer p.mu.Unlock()
	p.path, p.entries = a.placedFile(), map[string]placedEntry{}
	if p.path == "" {
		return
	}
	b, err := os.ReadFile(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var list []placedEntry
	if err == nil {
		err = json.Unmarshal(b, &list)
	}
	if err != nil {
		// Unreadable: nothing in it is a placement under the history trusted now. A handoff of a
		// copy already here is a replay (the safe side), as for a record that isn't there.
		a.placedOther = true
		a.log("placed under %s: %v: a handoff of a copy already here is kept until the record can be read", p.path, err)
		return
	}
	for _, e := range list {
		if e.UID == "" {
			continue
		}
		p.entries[e.UID] = e
		a.placedUnder.Store(e.UID, e.History)
		if e.History != a.historyAtStart {
			a.placedOther = true
		}
	}
}

// notePlaced records that the store read now places silo uid here, under the history trusted
// now. A history is written and synced before the caller goes on, so a restart sees it.
func (a *Agent) notePlaced(uid string) {
	hist := a.watermark().history()
	if v, ok := a.placedUnder.Load(uid); ok && v.(string) == hist {
		return
	}
	if hist == "" {
		if _, ok := a.placedUnder.Load(uid); !ok {
			a.placedUnder.Store(uid, "")
		}
		return // nothing trusted yet: the next placement under a history is the one kept on disk
	}
	a.placedUnder.Store(uid, hist)
	p := &a.placed
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entries == nil {
		p.entries = map[string]placedEntry{}
	}
	if p.path == "" {
		p.path = a.placedFile()
	}
	if e, ok := p.entries[uid]; ok && e.History == hist {
		return
	}
	p.entries[uid] = placedEntry{UID: uid, History: hist}
	if err := p.writeLocked(); err != nil {
		a.log("placed under %s: %v: the history %s was placed here under is kept in memory only", p.path, err, uid)
	}
}

// forgetPlaced drops silo uid once its copy is removed here.
func (a *Agent) forgetPlaced(uid string) {
	a.placedUnder.Delete(uid)
	p := &a.placed
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.entries[uid]; !ok {
		return
	}
	delete(p.entries, uid)
	if err := p.writeLocked(); err != nil {
		a.log("placed under %s: %v", p.path, err)
	}
}

func (p *placedLog) writeLocked() error {
	if p.path == "" {
		return nil
	}
	list := make([]placedEntry, 0, len(p.entries))
	for _, e := range p.entries {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].UID < list[j].UID })
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	d := deletesLog{path: p.path}
	return d.writeBytes(b)
}
