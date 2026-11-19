package agent_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
)

// A delete while this host was down is still in the log. The next run resumes from the revision
// it had reached, sees the delete, and removes the copy.
func TestADeleteWhileTheHostWasAwayIsSeen(t *testing.T) {
	r := newHistoryRig(t)
	stop := r.start(r.rt)
	r.trusted(seenA)
	r.id = r.place(r.cA, "hv1")
	r.waitFor("it runs", func() bool {
		st, _ := r.rt.Status(r.ctx, r.id)
		return st.State == kri.Running
	})
	watch := filepath.Join(filepath.Dir(r.file), agent.DeleteWatchFile)
	r.waitFor("the delete watch's revision is on disk", func() bool {
		b, err := os.ReadFile(watch)
		return err == nil && strings.Contains(string(b), `"revision"`) && strings.Contains(string(b), "c1/h1")
	})
	stop()
	if err := r.cA.Delete(r.ctx, "Silo", "dev", "single"); err != nil {
		t.Fatal(err)
	}
	r.start(r.rt)
	r.waitFor("the copy of the delete while this host was away is removed", func() bool {
		return !holds(r.t, r.rt, r.id.UID)
	})
}

// compactRev answers 410 for a watch of one revision: the log no longer has it.
type compactRev struct {
	next http.Handler
	rev  string
}

func (c *compactRev) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("watch") == "true" && r.URL.Query().Get("resourceVersion") == c.rev {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"code":410,"reason":"Expired","message":"revision compacted"}`))
		return
	}
	c.next.ServeHTTP(w, r)
}

// The persisted revision was compacted. The copy deleted in that gap stays. A delete after the
// watch has fallen back to the list's revision is seen, and that copy is removed.
func TestACompactedDeleteWatchKeepsTheGapAndSeesTheNext(t *testing.T) {
	r := newHistoryRig(t)
	stop := r.start(r.rt)
	r.trusted(seenA)
	r.id = r.place(r.cA, "hv1")
	r.waitFor("it runs", func() bool {
		st, _ := r.rt.Status(r.ctx, r.id)
		return st.State == kri.Running
	})
	var saved struct {
		Revision string `json:"revision"`
	}
	watch := filepath.Join(filepath.Dir(r.file), agent.DeleteWatchFile)
	r.waitFor("the delete watch's revision is on disk", func() bool {
		b, err := os.ReadFile(watch)
		return err == nil && json.Unmarshal(b, &saved) == nil && saved.Revision != ""
	})
	stop()
	// The agent may have written a later revision after the wait first saw the file. Compact the
	// revision the next start will actually resume from.
	b, err := os.ReadFile(watch)
	if err != nil || json.Unmarshal(b, &saved) != nil || saved.Revision == "" {
		t.Fatalf("delete watch after stop: %s %v", b, err)
	}
	if err := r.cA.Delete(r.ctx, "Silo", "dev", "single"); err != nil {
		t.Fatal(err)
	}
	r.cp.switchTo(&compactRev{next: r.srvA, rev: saved.Revision}, seenA)
	r.start(r.rt)
	r.trusted(seenA)
	r.keptFor(r.id, time.Second)
	next := r.place(r.cA, "hv1")
	r.waitFor("the next silo runs", func() bool {
		st, _ := r.rt.Status(r.ctx, next)
		return st.State == kri.Running
	})
	if err := r.cA.Delete(r.ctx, "Silo", "dev", "single"); err != nil {
		t.Fatal(err)
	}
	r.waitFor("a delete while this host is up is removed", func() bool {
		return !holds(r.t, r.rt, next.UID)
	})
	if !holds(r.t, r.rt, r.id.UID) {
		t.Fatal("the copy from the compacted gap was removed")
	}
}
