package guest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
)

// fakeBroker answers each connection with the next of its answers, recording the requests.
type fakeBroker struct {
	mu      sync.Mutex
	answers []client.BrokerResponse
	got     []client.BrokerRequest
}

func (f *fakeBroker) dial(context.Context) (net.Conn, error) {
	a, b := net.Pipe()
	go func() {
		defer func() { _ = b.Close() }()
		sc := bufio.NewScanner(b)
		if !sc.Scan() {
			return
		}
		var req client.BrokerRequest
		_ = json.Unmarshal(sc.Bytes(), &req)
		f.mu.Lock()
		f.got = append(f.got, req)
		resp := f.answers[0]
		if len(f.answers) > 1 {
			f.answers = f.answers[1:]
		}
		f.mu.Unlock()
		_ = json.NewEncoder(b).Encode(resp)
	}()
	return a, nil
}

func TestAskWaitsForTheYesWithoutReplacingTheRequest(t *testing.T) {
	wait := &client.ApprovalWait{Namespace: "agents", Name: "claude-1-ab12cd34", ExpiresAt: time.Now().Add(time.Minute)}
	f := &fakeBroker{answers: []client.BrokerResponse{{Pending: wait}, {Pending: wait}, {Value: []byte("tok")}}}
	var told []string
	resp, err := Ask(context.Background(), f.dial, client.BrokerRequest{Op: client.OpGetSecret, Name: "gh", For: "30m"}, time.Millisecond,
		func(a client.ApprovalWait) { told = append(told, a.Name) })
	if err != nil || string(resp.Value) != "tok" {
		t.Fatalf("Ask = %q, %v", resp.Value, err)
	}
	if len(f.got) != 3 || f.got[0].Approval != "" || f.got[1].Approval != wait.Name || f.got[2].Approval != wait.Name || f.got[2].For != "30m" {
		t.Fatalf("requests %+v: the first asks, the rest poll by name", f.got)
	}
	if len(told) != 1 {
		t.Fatalf("told %v, want once", told)
	}
}

func TestAskReportsADenial(t *testing.T) {
	wait := &client.ApprovalWait{Namespace: "agents", Name: "a"}
	f := &fakeBroker{answers: []client.BrokerResponse{{Pending: wait}, {Error: "approval a: denied by bob"}}}
	if _, err := Ask(context.Background(), f.dial, client.BrokerRequest{Op: client.OpSign, Name: "k"}, time.Millisecond, nil); err == nil || !strings.Contains(err.Error(), "denied by bob") {
		t.Fatalf("Ask = %v", err)
	}
}

// The context ends while Ask waits between polls (cancelled once the broker said "pending", with
// a poll interval it would never reach): no deadline racing the calls themselves.
func TestAskStopsWithTheContext(t *testing.T) {
	f := &fakeBroker{answers: []client.BrokerResponse{{Pending: &client.ApprovalWait{Name: "a"}}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := Ask(ctx, f.dial, client.BrokerRequest{Op: client.OpGetSecret, Name: "x"}, time.Hour, func(client.ApprovalWait) { cancel() })
	if err == nil || !strings.Contains(err.Error(), "stopped waiting") {
		t.Fatalf("Ask = %v", err)
	}
	if len(f.got) != 1 {
		t.Fatalf("%d requests, want the one", len(f.got))
	}
}

func TestSecretGetFlags(t *testing.T) {
	f := &fakeBroker{answers: []client.BrokerResponse{{Value: []byte("v")}}}
	var out, errs bytes.Buffer
	if err := run(context.Background(), f.dial, "/", []string{"secret", "get", "gh", "--for", "5m", "--wait", "2m"}, nil, &out, &errs); err != nil || out.String() != "v" {
		t.Fatalf("run = %q, %v", out.String(), err)
	}
	if f.got[0].For != "5m" || f.got[0].Wait != "2m" {
		t.Fatalf("request %+v", f.got[0])
	}
	for _, bad := range [][]string{{"secret", "get", "gh", "--for"}, {"secret", "get", "gh", "--for", "soon"}, {"secret", "get", "gh", "--nope", "1m"}} {
		if err := run(context.Background(), f.dial, "/", bad, nil, &out, &errs); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestPaneReportFlags(t *testing.T) {
	f := &fakeBroker{answers: []client.BrokerResponse{{}}}
	var out, errs bytes.Buffer
	err := run(context.Background(), f.dial, "/", []string{"pane", "report", "overview", "--state", "needs-you", "--progress", "0.5",
		"--title", "claude", "--field", "tests=212/240", "--ttl", "60s"}, nil, &out, &errs)
	if err != nil || out.String() != "ok\n" {
		t.Fatalf("%q %v", out.String(), err)
	}
	p := f.got[0].Pane
	if f.got[0].Op != client.OpPane || p.Kind != "status" || p.State != "needs-you" || *p.Progress != 0.5 || p.Fields[0].Value != "212/240" {
		t.Fatalf("report %+v", p)
	}
	for _, bad := range [][]string{{"pane", "report", "x", "--progress", "lots"}, {"pane", "report", "x", "--bundle", "f"}, {"pane", "html", "x"}, {"pane", "nope", "x"}} {
		if err := run(context.Background(), f.dial, "/", bad, nil, &out, &errs); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestPaneHTMLUploadsThenReports(t *testing.T) {
	f := &fakeBroker{answers: []client.BrokerResponse{{Digest: "sha256:" + strings.Repeat("a", 64)}, {}}}
	dir := t.TempDir()
	bundle := dir + "/pane.html"
	_ = os.WriteFile(bundle, []byte("<canvas></canvas>"), 0o600)
	var out, errs bytes.Buffer
	if err := run(context.Background(), f.dial, "/", []string{"pane", "html", "fleet", "--bundle", bundle, "--data", `{"lit":3}`}, nil, &out, &errs); err != nil {
		t.Fatal(err)
	}
	if f.got[0].Op != client.OpPaneBundle || string(f.got[0].Payload) != "<canvas></canvas>" || f.got[1].Pane.Bundle != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("requests %+v", f.got)
	}
}
