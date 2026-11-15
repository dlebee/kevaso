package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"kevaso.com/core/internal/engine"
	"kevaso.com/core/sdk/kri"
)

// K-068 (b): the copies this host keeps though the control plane doesn't know them (KeptSilos)
// are listed for a person in KeptFile, and one is removed when a person asks for it, confirmed,
// through KeptRemoveDir (kvoadm host kept HOST [--remove NS/NAME/UID]): a delete this host never
// saw, made on the strength of that confirmation.
const (
	// KeptFile lists the kept copies, beside the seen deletes (kevasod --data).
	KeptFile = "kept-silos.json"
	// KeptRemoveDir holds one file per removal asked for, named by the silo's UID.
	KeptRemoveDir = "kept-remove"
)

// KeptEntry is one kept copy, as KeptFile lists it.
type KeptEntry struct {
	UID       string `json:"uid"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Runtime   string `json:"runtime"`
	What      string `json:"what"` // how KeptSilos lists it
}

func (a *Agent) dataDir() string {
	if p := a.deletesFile(); p != "" {
		return filepath.Dir(p)
	}
	return ""
}

// writeKeptFile writes the kept copies for kvoadm host kept (nothing without a data folder).
func (a *Agent) writeKeptFile() {
	dir := a.dataDir()
	if dir == "" {
		return
	}
	list := []KeptEntry{}
	a.keptNoted.Range(func(k, v any) bool {
		if c, ok := v.(keptCopy); ok && c.id.UID != "" {
			list = append(list, KeptEntry{UID: c.id.UID, Namespace: c.id.Namespace, Name: c.id.Name, Runtime: c.runtime, What: c.name})
		}
		return true
	})
	sort.Slice(list, func(i, j int) bool { return list[i].UID < list[j].UID })
	b, _ := json.MarshalIndent(list, "", "  ")
	d := deletesLog{path: filepath.Join(dir, KeptFile)}
	if err := d.writeBytes(b); err != nil {
		a.log("kept silos %s: %v", d.path, err)
	}
}

// takeKeptRemovals reads the removals a person asked for: each names a kept copy by its UID. One
// this host keeps is removed (removeEverywhere, mayRemove: the confirmation is the proof); any
// other request is dropped, said in the log.
func (a *Agent) takeKeptRemovals() {
	dir := a.dataDir()
	if dir == "" {
		return
	}
	reqs, err := os.ReadDir(filepath.Join(dir, KeptRemoveDir))
	if err != nil {
		return
	}
	for _, r := range reqs {
		uid := r.Name()
		v, kept := a.keptNoted.Load(uid)
		c, _ := v.(keptCopy)
		if !kept || c.id.UID == "" {
			a.log("a removal was asked for %s, which isn't a copy this host keeps: nothing removed", uid)
			_ = os.Remove(filepath.Join(dir, KeptRemoveDir, uid))
			continue
		}
		if _, again := a.removeConfirmed.LoadOrStore(uid, c.id); !again {
			a.log("removing %s on a person's confirmation (kvoadm host kept --remove): its disk and volumes go", c.name)
		}
		if a.engine != nil {
			a.engine.Changed(engine.Key{Kind: "Silo", Namespace: c.id.Namespace, Name: c.id.Name})
		}
	}
}

func (a *Agent) removalConfirmed(uid string) bool {
	_, ok := a.removeConfirmed.Load(uid)
	return ok
}

// removalDone forgets a confirmed removal once nothing of the copy is left here.
func (a *Agent) removalDone(uid string) {
	if v, ok := a.removeConfirmed.LoadAndDelete(uid); ok {
		a.log("%s removed, as a person confirmed", v.(kri.ID))
		if dir := a.dataDir(); dir != "" {
			_ = os.Remove(filepath.Join(dir, KeptRemoveDir, uid))
		}
	}
}
