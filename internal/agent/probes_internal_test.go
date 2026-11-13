package agent

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/probes"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// noExec is a runtime that can't exec in its silos.
type noExec struct{ *fake.Runtime }

func (n noExec) Info() kri.Info {
	i := n.Runtime.Info()
	i.Capabilities.Exec = false
	return i
}

// One run of each kind of probe, from the host: what passes, what fails, and what can't run.
func TestRunProbe(t *testing.T) {
	var status int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			status = 404
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	var dialled string
	a := &Agent{Clock: clock.Real{}, ProbeDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialled = addr
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Listener.Addr().String())
	}}
	rt := fake.New()
	rt.Handler = func(_ kri.ID, cmd []string, _ []byte) (string, int) {
		if cmd[0] == "false" {
			return "not synced: block 12", 1
		}
		return "ok", 0
	}
	s := &v1.Silo{Spec: v1.SiloSpec{Runtime: "fake", Service: &v1.SiloService{Ports: []v1.ServicePort{{Name: "rpc", Port: 8545}}}}}
	s.Namespace, s.Name, s.UID = "web3", "rpc", "u"
	_ = rt.Create(context.Background(), kri.Spec{ID: idOf(s)})
	_ = rt.Start(context.Background(), idOf(s))
	run := func(rt kri.Runtime, addr string, p *v1.Probe) probes.Outcome {
		return a.runProbe(context.Background(), rt, s, addr, probes.Named{Name: v1.ProbeReadiness, Probe: p})
	}
	httpP := &v1.Probe{HTTP: &v1.HTTPProbe{Port: "rpc", Path: "/health"}}
	for _, tc := range []struct {
		name   string
		status int
		rt     kri.Runtime
		addr   string
		p      *v1.Probe
		result string
		reason string
	}{
		{"http 200", 200, rt, "10.64.1.2", httpP, v1.ResultSuccess, "HTTP 200"},
		{"http 302 passes", 302, rt, "10.64.1.2", httpP, v1.ResultSuccess, "HTTP 302"},
		{"http 503 fails", 503, rt, "10.64.1.2", httpP, v1.ResultFailure, "503"},
		{"tcp", 0, rt, "10.64.1.2", &v1.Probe{TCP: &v1.TCPProbe{Port: "8545"}}, v1.ResultSuccess, "connected"},
		{"exec passes", 0, rt, "", &v1.Probe{Exec: &v1.ExecProbe{Command: []string{"true"}}}, v1.ResultSuccess, ""},
		{"exec fails with the end of its output", 0, rt, "", &v1.Probe{Exec: &v1.ExecProbe{Command: []string{"false"}}}, v1.ResultFailure, "exit 1: not synced: block 12"},
		{"no exec: can't run", 0, noExec{rt}, "", &v1.Probe{Exec: &v1.ExecProbe{Command: []string{"true"}}}, v1.ResultCantRun, "can't exec"},
		{"no address: can't run", 0, rt, "", &v1.Probe{TCP: &v1.TCPProbe{Port: "rpc"}}, v1.ResultCantRun, "no address"},
		{"not a service port: can't run", 0, rt, "10.64.1.2", &v1.Probe{TCP: &v1.TCPProbe{Port: "web"}}, v1.ResultCantRun, "isn't one of the service's ports"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, dialled = tc.status, ""
			o := run(tc.rt, tc.addr, tc.p)
			if o.Result != tc.result || !strings.Contains(o.Reason, tc.reason) {
				t.Fatalf("%+v", o)
			}
			if tc.addr != "" && tc.result != v1.ResultCantRun && dialled != tc.addr+":8545" {
				t.Fatalf("dialled %q, want the silo's own address", dialled)
			}
		})
	}
	// A dial that fails is a failure, with the error.
	a.ProbeDial = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	}
	if o := run(rt, "10.64.1.2", &v1.Probe{TCP: &v1.TCPProbe{Port: "rpc"}}); o.Result != v1.ResultFailure || !strings.Contains(o.Reason, "refused") {
		t.Fatalf("refused: %+v", o)
	}
	// A run past its limit is a failure, not can't-run.
	rt.Program = func(ctx context.Context, _ kri.ID, _ kri.ExecRequest) int { <-ctx.Done(); return -1 }
	if o := run(rt, "", &v1.Probe{Exec: &v1.ExecProbe{Command: []string{"sleep"}}, Timeout: "50ms"}); o.Result != v1.ResultFailure || !strings.Contains(o.Reason, "timed out") {
		t.Fatalf("timeout: %+v", o)
	}
}

type errRefused struct{}

func (errRefused) Error() string { return "connection refused" }
