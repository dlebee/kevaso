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
	list  string
	asked []string
}

func (h *keptHost) Run(_ context.Context, cmd string, _ []byte) ([]byte, error) {
	switch {
	case cmd == KeptListScript("/var/lib/kevaso"):
		return []byte(h.list), nil
	case strings.Contains(cmd, agent.KeptRemoveDir):
		for _, uid := range []string{"1111aaaa-0000", "2222bbbb-0000"} {
			if cmd == KeptRemoveScript("/var/lib/kevaso", uid) {
				h.asked = append(h.asked, uid)
				h.list = strings.Replace(h.list, `{"uid":"`+uid+`","namespace":"dev","name":"db","runtime":"docker","what":"dev/db uid 1111aaaa (docker)"}`, "", 1)
				h.list = strings.ReplaceAll(h.list, "[,", "[")
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
	if err != nil || len(h.asked) != 1 || h.asked[0] != "1111aaaa-0000" || !strings.Contains(out, "removed") {
		t.Fatalf("confirmed: %v, asked %v\n%s", err, h.asked, out)
	}
}
