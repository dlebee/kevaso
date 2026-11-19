package agent

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

// DeleteWatchFile is the last silo-watch revision this host saw, beside its control-plane
// watermark. The next run resumes there, so a delete that happened while kevasod was down is
// still in the log. A missing or unreadable file starts at the list's revision, which is what a
// host that has never watched does: those deletes stay unseen and the copies stay.
const DeleteWatchFile = "delete-watch.json"

// deleteWatchFile is the persisted revision and the history it belongs to (Watermark.history,
// cluster/history). A resume uses it only when the history is still that one.
type deleteWatchFile struct {
	History  string `json:"history"`
	Revision string `json:"revision"`
}

func (a *Agent) deleteWatchPath() string {
	w := a.watermark()
	if w == nil || w.path == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(w.path), DeleteWatchFile)
}

// savedDeleteWatch reads the revision the last run left. ok is false when there is nowhere to
// keep it, the file is missing, or it cannot be read: nothing in it is resumed from.
func (a *Agent) savedDeleteWatch() (deleteWatchFile, bool) {
	path := a.deleteWatchPath()
	if path == "" {
		return deleteWatchFile{}, false
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return deleteWatchFile{}, false
	}
	var saved deleteWatchFile
	if err == nil {
		err = json.Unmarshal(b, &saved)
	}
	if err != nil || saved.Revision == "" {
		a.log("delete watch %s: %v: starting at the list's revision, so a delete while this host was away is not seen and that copy is kept", path, err)
		return deleteWatchFile{}, false
	}
	return saved, true
}

// saveDeleteWatch records rev under hist, after the event is handled. A revision that is not
// past the one already stored is left, so a replay does not move the file backwards. Nothing is
// written before a resumed backlog has been consumed: a crash then replays it instead of skipping it.
func (a *Agent) saveDeleteWatch(hist, rev string) {
	if hist == "" || rev == "" {
		return
	}
	path := a.deleteWatchPath()
	if path == "" {
		return
	}
	if cur, ok := a.savedDeleteWatch(); ok && cur.History == hist && !revLess(cur.Revision, rev) {
		return
	}
	b, err := json.Marshal(deleteWatchFile{History: hist, Revision: rev})
	if err != nil {
		return
	}
	if err := writeAtomic(path, b); err != nil {
		a.log("delete watch %s: %v", path, err)
	}
}

// noteDeleteWatch advances the persisted revision to the event's object, once it has been handled.
func (a *Agent) noteDeleteWatch(hist string, raw []byte) {
	o, _, err := v1.Decode(raw)
	if err != nil || o == nil {
		return
	}
	a.saveDeleteWatch(hist, o.GetObjectMeta().ResourceVersion)
}

// revLess reports whether a is a lower store revision than b. Non-numeric revisions are not
// ordered, so they are not resumed from.
func revLess(a, b string) bool {
	ia, ea := strconv.ParseUint(a, 10, 64)
	ib, eb := strconv.ParseUint(b, 10, 64)
	if ea != nil || eb != nil {
		return false
	}
	return ia < ib
}

// watchCompacted reports a watch the store can no longer serve from that revision (HTTP 410).
func watchCompacted(err error) bool {
	var e *client.Error
	return errors.As(err, &e) && e.Code == http.StatusGone
}

// writeAtomic writes b to path the way seen deletes are written: a temp file, synced, then renamed,
// and the directory synced, so a crash leaves the previous file or the new one.
func writeAtomic(path string, b []byte) error {
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
	df, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = df.Close() }()
	return df.Sync()
}
