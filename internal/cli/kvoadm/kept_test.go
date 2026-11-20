package kvoadm

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/agent"
)

// keptHost is a worker's data folder as kvoadm host kept sees it over SSH: its list of kept
// copies, and the removal requests written; the worker removes a requested copy at once.
type keptHost struct {
	list     string
	asked    []string
	removed  map[string]bool
	unlisted bool // the UID leaves the list and the worker does not say it removed the copy
}

func (h *keptHost) Run(_ context.Context, cmd string, _ []byte) ([]byte, error) {
	switch {
	case cmd == KeptListScript("/var/lib/kevaso"):
		return []byte(h.list), nil
	case strings.Contains(cmd, agent.KeptRemovedDir):
		for uid, ok := range h.removed {
			if ok && cmd == KeptRemovedScript("/var/lib/kevaso", uid) {
				return []byte("removed\n"), nil
			}
		}
		return []byte("\n"), nil
	case strings.Contains(cmd, agent.KeptRemoveDir):
		for _, uid := range []string{"1111aaaa-0000", "2222bbbb-0000"} {
			if cmd == KeptRemoveScript("/var/lib/kevaso", uid) {
				h.asked = append(h.asked, uid)
				h.list = strings.Replace(h.list, `{"uid":"`+uid+`","namespace":"dev","name":"db","runtime":"docker","what":"dev/db uid 1111aaaa (docker)"}`, "", 1)
				h.list = strings.Replace(h.list, `{"uid":"`+uid+`","namespace":"dev","name":"web","runtime":"docker","what":"dev/web uid 2222bbbb (docker, stopped: placed on \"hv2\" with no handoff from this host)"}`, "", 1)
				h.list = strings.ReplaceAll(h.list, "[,", "[")
				h.list = strings.ReplaceAll(h.list, ",]", "]")
				if !h.unlisted {
					if h.removed == nil {
						h.removed = map[string]bool{}
					}
					h.removed[uid] = true
				}
				return []byte("asked\n"), nil
			}
		}
	}
	return nil, nil
}

// K-068 (b): kvoadm host kept lists a worker's kept copies, and removes one only once a person
// typed its name; a copy the worker doesn't keep, or a name that doesn't match, removes nothing.
func TestHostKeptListsAndRemovesOnlyOnConfirmation(t *testing.T) {
	list := `[{"uid":"1111aaaa-0000","namespace":"dev","name":"db","runtime":"docker","what":"dev/db uid 1111aaaa (docker)"},{"uid":"2222bbbb-0000","namespace":"dev","name":"web","runtime":"docker","what":"dev/web uid 2222bbbb (docker, stopped: placed on \"hv2\" with no handoff from this host)"}]`
	run := func(h *keptHost, remove, answer string) (string, error) {
		var out strings.Builder
		o := KeptOptions{TrustOptions: TrustOptions{Data: "/var/lib/kevaso"}, Remove: remove}
		o.Address = "203.0.113.20"
		err := runKept(context.Background(), h, o, bufio.NewReader(strings.NewReader(answer)), &out, time.Millisecond)
		return out.String(), err
	}
	h := &keptHost{list: list}
	out, err := run(h, "", "")
	if err != nil || !strings.Contains(out, "dev/db") || !strings.Contains(out, "2222bbbb-0000") || len(h.asked) != 0 {
		t.Fatalf("list: %v\n%s", err, out)
	}
	for _, c := range []struct{ remove, answer string }{
		{"dev/db/1111aaaa", "dev/web\n"}, // the wrong name typed
		{"dev/db/1111aaaa", "\n"},
		{"dev/db/3333cccc", "dev/db\n"}, // not a kept copy
		{"dev/db/1111", "dev/db\n"},     // too little of the UID
	} {
		if _, err := run(h, c.remove, c.answer); err == nil || len(h.asked) != 0 {
			t.Fatalf("--remove %s answered %q: %v, asked %v", c.remove, c.answer, err, h.asked)
		}
	}
	out, err = run(h, "dev/db/1111aaaa", "dev/db\n")
	if err != nil || len(h.asked) != 1 || h.asked[0] != "1111aaaa-0000" || !strings.Contains(out, "removed from") {
		t.Fatalf("confirmed: %v, asked %v\n%s", err, h.asked, out)
	}
	if !strings.Contains(out, "nothing else holds this data") {
		t.Fatalf("a copy the control plane doesn't know wasn't described that way:\n%s", out)
	}
}

// A copy the store places elsewhere is stopped here. The prompt says so, and does not say the
// control plane doesn't know it. Leaving the kept list, without the worker saying it removed the
// copy, is not reported as removed.
func TestHostKeptDescribesAPlacedCopyAndDoesNotCallItRemoved(t *testing.T) {
	list := `[{"uid":"2222bbbb-0000","namespace":"dev","name":"web","runtime":"docker","what":"dev/web uid 2222bbbb (docker, stopped: placed on \"hv2\" with no handoff from this host)"}]`
	h := &keptHost{list: list}
	var out strings.Builder
	o := KeptOptions{TrustOptions: TrustOptions{Data: "/var/lib/kevaso"}, Remove: "dev/web/2222bbbb"}
	o.Address = "203.0.113.20"
	err := runKept(context.Background(), h, o, bufio.NewReader(strings.NewReader("nope\n")), &out, time.Millisecond)
	if err == nil || strings.Contains(out.String(), "nothing else holds this data") || strings.Contains(out.String(), "doesn't know") {
		t.Fatalf("a copy the store places elsewhere: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "stopped copy") {
		t.Fatalf("the prompt doesn't say this host keeps a stopped copy:\n%s", out.String())
	}
	h = &keptHost{list: list, unlisted: true}
	out.Reset()
	o.Yes = true
	err = runKept(context.Background(), h, o, bufio.NewReader(strings.NewReader("")), &out, time.Millisecond)
	if err == nil || strings.Contains(out.String(), "removed from") {
		t.Fatalf("leaving the list was called removed: %v\n%s", err, out.String())
	}
}

func TestHostKeptSaysWhatGoesHereAndWhatStays(t *testing.T) {
	list := `[{"uid":"1111aaaa-0000","namespace":"dev","name":"db","runtime":"cloud-hypervisor","what":"dev/db uid 1111aaaa (cloud-hypervisor, stopped: placed on \"hv2\" with no handoff from this host)","shared":"juicefs","onHost":true}]`
	h := &keptHost{list: list}
	var out strings.Builder
	o := KeptOptions{TrustOptions: TrustOptions{Data: "/var/lib/kevaso"}, Remove: "dev/db/1111aaaa"}
	o.Address = "203.0.113.20"
	err := runKept(context.Background(), h, o, bufio.NewReader(strings.NewReader("nope\n")), &out, time.Millisecond)
	if err == nil {
		t.Fatal("an unconfirmed removal succeeded")
	}
	text := out.String()
	if !strings.Contains(text, "its disk and its volumes on 203.0.113.20, for good") || !strings.Contains(text, "The volumes on juicefs stay") {
		t.Fatalf("prompt:\n%s", text)
	}
	if strings.Contains(text, "only this host's copy") {
		t.Fatalf("a copy with a disk on this host was said to delete only the copy:\n%s", text)
	}
}

func TestHostKeptSaysATravellingVolumeStays(t *testing.T) {
	list := `[{"uid":"1111aaaa-0000","namespace":"dev","name":"db","runtime":"cloud-hypervisor","what":"dev/db uid 1111aaaa (cloud-hypervisor, stopped: placed on \"hv2\" with no handoff from this host)","shared":"juicefs"}]`
	h := &keptHost{list: list}
	var out strings.Builder
	o := KeptOptions{TrustOptions: TrustOptions{Data: "/var/lib/kevaso"}, Remove: "dev/db/1111aaaa"}
	o.Address = "203.0.113.20"
	err := runKept(context.Background(), h, o, bufio.NewReader(strings.NewReader("nope\n")), &out, time.Millisecond)
	if err == nil {
		t.Fatal("an unconfirmed removal succeeded")
	}
	if !strings.Contains(out.String(), "only this host's copy") || !strings.Contains(out.String(), "the volumes on juicefs stay") {
		t.Fatalf("prompt:\n%s", out.String())
	}
	if strings.Contains(out.String(), "its disk and its volumes") {
		t.Fatalf("the prompt says the travelling volumes go:\n%s", out.String())
	}
}
