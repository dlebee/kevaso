package guest

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
)

func TestPortCommand(t *testing.T) {
	old := PollEvery
	PollEvery = time.Millisecond
	defer func() { PollEvery = old }()
	until := time.Now().Add(time.Hour)
	wait := &client.ApprovalWait{Namespace: "dev", Name: "api-ab12cd34", ExpiresAt: time.Now().Add(time.Minute)}
	f := &fakeBroker{answers: []client.BrokerResponse{{Pending: wait, Clamped: true}, {Until: &until, Clamped: true}}}
	var out, errs bytes.Buffer
	if err := run(context.Background(), f.dial, t.TempDir(), []string{"port", "open", "debug", "--for", "5h"}, nil, &out, &errs); err != nil {
		t.Fatal(err)
	}
	if f.got[0].Op != client.OpPortOpen || f.got[0].Name != "debug" || f.got[0].For != "5h" || f.got[1].Approval != wait.Name {
		t.Fatalf("requests %+v", f.got)
	}
	if !strings.HasPrefix(out.String(), "port debug open until ") || !strings.Contains(errs.String(), "kvo approve api-ab12cd34 -n dev") ||
		!strings.Contains(errs.String(), "more than its lease's max") {
		t.Fatalf("out %q, err %q", out.String(), errs.String())
	}
	f = &fakeBroker{answers: []client.BrokerResponse{{Until: &until}}}
	out.Reset()
	if err := run(context.Background(), f.dial, t.TempDir(), []string{"port", "close", "debug"}, nil, &out, &errs); err != nil || out.String() != "port debug closed\n" || f.got[0].Op != client.OpPortClose {
		t.Fatalf("close: %q %v %+v", out.String(), err, f.got)
	}
	if err := run(context.Background(), f.dial, t.TempDir(), []string{"port", "open"}, nil, &out, &errs); err == nil {
		t.Fatal("no name: no error")
	}
}
