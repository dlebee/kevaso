package agent_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
)

// K-068 (b): a kept copy (the control plane doesn't know it, no delete of it was seen) is listed
// for a person (agent.KeptFile, read by kvoadm host kept), and removed, disk and volumes with it,
// once a person asks for it (a file named by its UID in agent.KeptRemoveDir, written by kvoadm host
// kept --remove after confirmation). Nothing else is removed, and a request for a copy that isn't
// kept removes nothing.
func TestAKeptCopyIsListedAndRemovedOnAPersonsConfirmation(t *testing.T) {
	r := newHistoryRig(t)
	id := kri.ID{Namespace: "dev", Name: "single", UID: "0c0ffee0-0000-0000-0000-000000000000"}
	other := kri.ID{Namespace: "dev", Name: "other", UID: "0d0ffee0-0000-0000-0000-000000000000"}
	for _, x := range []kri.ID{id, other} {
		if err := r.rt.Create(r.ctx, kri.Spec{ID: x, Image: "ubuntu-24.04"}); err != nil {
			t.Fatal(err)
		}
	}
	r.start(r.rt)
	r.trusted(seenA)
	r.listed(r.cA, id)
	dir := filepath.Dir(r.file)
	listed := func() map[string]bool {
		var l []agent.KeptEntry
		b, _ := os.ReadFile(filepath.Join(dir, agent.KeptFile))
		_ = json.Unmarshal(b, &l)
		m := map[string]bool{}
		for _, e := range l {
			m[e.Namespace+"/"+e.Name+"/"+e.UID] = true
		}
		return m
	}
	r.waitFor("both copies in "+agent.KeptFile, func() bool {
		r.clk.Step(time.Second)
		m := listed()
		return m["dev/single/"+id.UID] && m["dev/other/"+other.UID]
	})
	if err := os.MkdirAll(filepath.Join(dir, agent.KeptRemoveDir), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{id.UID, "not-a-kept-copy"} {
		if err := os.WriteFile(filepath.Join(dir, agent.KeptRemoveDir, uid), []byte("dev/single\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r.waitFor("the confirmed copy removed", func() bool { r.clk.Step(time.Second); return !holds(t, r.rt, id.UID) })
	r.waitFor("no longer listed, and its request gone", func() bool {
		r.clk.Step(time.Second)
		_, err := os.Stat(filepath.Join(dir, agent.KeptRemoveDir, id.UID))
		b, _ := os.ReadFile(filepath.Join(dir, agent.KeptRemovedDir, id.UID))
		return !listed()["dev/single/"+id.UID] && os.IsNotExist(err) && string(b) == "removed\n"
	})
	if _, err := os.Stat(filepath.Join(dir, agent.KeptRemoveDir, "not-a-kept-copy")); !os.IsNotExist(err) {
		t.Fatal("a request for a copy that isn't kept was left")
	}
	r.keptFor(other, time.Second)
}
