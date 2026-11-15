package kvoadm

import (
	"bufio"
	"context"
	"strings"
	"testing"
)

type trustHost struct {
	file string // what the record holds; "-" for no file
	ran  []string
}

func (h *trustHost) Run(_ context.Context, cmd string, _ []byte) ([]byte, error) {
	h.ran = append(h.ran, cmd)
	switch cmd {
	case TrustLookScript("/var/lib/kevaso/" + WatermarkFile):
		if h.file == "-" {
			return []byte("absent\n"), nil
		}
		return []byte("present\n" + h.file), nil
	case TrustSetAsideScript("/var/lib/kevaso/" + WatermarkFile):
		return []byte("done\n"), nil
	}
	return nil, nil
}

func (h *trustHost) setAside() bool {
	for _, c := range h.ran {
		if strings.Contains(c, "mv ") {
			return true
		}
	}
	return false
}

// K-096: recovery from an unreadable watermark is a person's explicit act. kvoadm sets aside
// (keeps) only a record that is really unreadable, after a yes; a readable one is never touched
// (a hold is released by a new history, not by this).
func TestTrustControlPlaneSetsAsideOnlyAnUnreadableRecord(t *testing.T) {
	run := func(h *trustHost, yes bool, answer string) (string, error) {
		var out strings.Builder
		o := TrustOptions{Data: "/var/lib/kevaso", Yes: yes}
		o.Address = "203.0.113.20"
		err := runTrust(context.Background(), h, o, bufio.NewReader(strings.NewReader(answer)), &out)
		return out.String(), err
	}
	h := &trustHost{file: `{"clusterID":"c1","revis`}
	if _, err := run(h, false, "no\n"); err == nil || h.setAside() {
		t.Fatalf("not confirmed: %v, set aside %v", err, h.setAside())
	}
	h = &trustHost{file: `{}`}
	out, err := run(h, false, "yes\n")
	if err != nil || !h.setAside() || !strings.Contains(out, "it names no cluster") {
		t.Fatalf("an unreadable record, confirmed: %v, set aside %v\n%s", err, h.setAside(), out)
	}
	h = &trustHost{file: `{"clusterID":"c1","history":"h1","epoch":1,"revision":10,"held":true}`}
	if _, err := run(h, true, ""); err == nil || h.setAside() || !strings.Contains(err.Error(), "kvoadm init --restore") {
		t.Fatalf("a readable (held) record was set aside: %v", err)
	}
	h = &trustHost{file: "-"}
	if _, err := run(h, true, ""); err != nil || h.setAside() {
		t.Fatalf("no record: %v", err)
	}
}
