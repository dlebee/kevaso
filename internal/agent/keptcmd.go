package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	v1 "kevaso.com/core/api/v1"
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
	// KeptRemovedDir holds one file per copy actually removed, named by the silo's UID.
	// kvoadm host kept reads it: the UID leaving the kept list is not, by itself, a removal.
	KeptRemovedDir = "kept-removed"
)

// KeptEntry is one kept copy, as KeptFile lists it.
type KeptEntry struct {
	UID       string `json:"uid"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Runtime   string `json:"runtime"`
	What      string `json:"what"` // how KeptSilos lists it
	// Shared is the storage class of a disk or volume that travels with the silo.
	// Empty when nothing of this copy travels.
	Shared string `json:"shared,omitempty"`
	// OnHost is set with Shared when this copy also holds a disk or volume on this host.
	// Removing it then deletes what is here and leaves what is on Shared.
	OnHost bool `json:"onHost,omitempty"`
}

// siloCached is the silo of id as this host's cache has it, or nil.
func (a *Agent) siloCached(id kri.ID) *v1.Silo {
	if a.silos == nil {
		return nil
	}
	o, ok := a.silos.Get(id.Namespace, id.Name)
	if !ok {
		return nil
	}
	s, ok := o.(*v1.Silo)
	if !ok || s.UID != id.UID {
		return nil
	}
	return s
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
			e := KeptEntry{UID: c.id.UID, Namespace: c.id.Namespace, Name: c.id.Name, Runtime: c.runtime, What: c.name}
			e.Shared, e.OnHost = a.keptClasses(c)
			list = append(list, e)
		}
		return true
	})
	sort.Slice(list, func(i, j int) bool { return list[i].UID < list[j].UID })
	b, _ := json.MarshalIndent(list, "", "  ")
	if prev, _ := a.keptWritten.Load().(string); prev == string(b) {
		return // as written already
	}
	d := deletesLog{path: filepath.Join(dir, KeptFile)}
	if err := d.writeBytes(b); err != nil {
		a.log("kept silos %s: %v", d.path, err)
		return
	}
	a.keptWritten.Store(string(b))
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
		shared, onHost := a.keptClasses(c)
		if _, again := a.removeConfirmed.LoadOrStore(uid, c.id); !again {
			switch {
			case shared != "" && !onHost: // a travelling class is not this host's to delete
				a.log("removing %s on a person's confirmation (kvoadm host kept --remove): only this host's copy; the volumes on %s stay", c.name, shared)
			case shared != "" && onHost: // this host's disk goes; what is on the class stays
				a.log("removing %s on a person's confirmation (kvoadm host kept --remove): its disk and volumes on this host go, for good; the volumes on %s stay", c.name, shared)
			default:
				a.log("removing %s on a person's confirmation (kvoadm host kept --remove): its disk and volumes go", c.name)
			}
		}
		// Placed here again while this was read: the confirmation is already void.
		if _, still := a.keptNoted.Load(uid); !still {
			a.dropRemovalConfirmation(uid)
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

// dropRemovalConfirmation forgets a person's removal once the store places that copy here
// again. The confirmation was for a copy the control plane didn't have; it does not stay and
// delete the copy if the store later places it elsewhere or loses it.
func (a *Agent) dropRemovalConfirmation(uid string) {
	if _, ok := a.removeConfirmed.LoadAndDelete(uid); !ok {
		return
	}
	a.log("a confirmed removal of %s is dropped: the store places that copy here", uid)
	if dir := a.dataDir(); dir != "" {
		_ = os.Remove(filepath.Join(dir, KeptRemoveDir, uid))
	}
}

// removalDone forgets a confirmed removal once nothing of the copy is left here.
func (a *Agent) removalDone(uid string) {
	if v, ok := a.removeConfirmed.LoadAndDelete(uid); ok {
		a.log("%s removed, as a person confirmed", v.(kri.ID))
		if dir := a.dataDir(); dir != "" {
			_ = os.Remove(filepath.Join(dir, KeptRemoveDir, uid))
			d := filepath.Join(dir, KeptRemovedDir)
			if err := os.MkdirAll(d, 0o700); err == nil {
				_ = os.WriteFile(filepath.Join(d, uid), []byte("removed\n"), 0o600)
			}
		}
	}
}
