package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/keep"
	"kevaso.com/core/internal/probes"
	"kevaso.com/core/sdk/kri"
)

// Probes (design §0.6) run on the silo's own host, never from the control plane:
//
//   - exec goes through the runtime's exec, like init steps and upkeep;
//   - tcp and http dial the silo's own silo IP (status.siloIP) from the host itself.
//     The host is the silos' gateway on its bridge, so this traffic starts on the host and goes
//     out through its own output path: it never crosses the forward chain, where silo-to-silo
//     (allowFrom) and outside (host ports, load balancers, grants) rules live, so it needs no allowFrom entry,
//     no grant and no port on the host, and opens nothing to anyone else. The silo's replies to the
//     gateway are let in as established traffic (the input chain). Never the host's or a load balancer's address: a
//     probe says whether the silo answers, not whether the outside can reach it.
//
// A probe that can't run is CantRun, never a failure: the runtime has no exec, the silo has no
// address its host reaches (openshell has no network card), or the port names no service port.

// probeState is what the agent last decided about one silo's probes: what it read can be older
// than its own last write, and a probe must not run twice in one period because of it.
type probeState struct {
	probes []v1.ProbeStatus
}

// probeOutcome is what a round of probes decided for a running silo.
type probeOutcome struct {
	statuses []v1.ProbeStatus
	conds    []probes.Condition
	restart  bool
	next     time.Duration // when to look again (0: nothing to probe)
}

func (a *Agent) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if a.ProbeDial != nil {
		return a.ProbeDial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// probe runs the probes due now for a running silo (init done) at address, and decides its
// conditions and whether liveness asks for a restart.
func (a *Agent) probe(ctx context.Context, rt kri.Runtime, s *v1.Silo, address string, startedAt time.Time) probeOutcome {
	now := a.now()
	prev := s.Status.Probes
	if mine, ok := a.probed.Load(s.UID); ok {
		prev = newer(prev, mine.(probeState).probes)
	}
	st := probes.Normalize(s.Spec.Probes, prev, startedAt, now)
	due, _ := probes.Due(s.Spec.Probes, st, startedAt, now)
	for _, name := range due {
		for _, n := range probes.List(s.Spec.Probes) {
			if n.Name != name {
				continue
			}
			o := a.runProbe(ctx, rt, s, address, n)
			cur := v1.FindProbe(st, name)
			*cur = probes.Record(name, n.Probe, *cur, o, now)
		}
		// One passing startup lets readiness and liveness start in the same round.
		st = probes.Normalize(s.Spec.Probes, st, startedAt, now)
	}
	_, next := probes.Due(s.Spec.Probes, st, startedAt, now)
	a.probed.Store(s.UID, probeState{probes: st})
	restart, wait := probes.OnLiveness(s.Spec.Probes, st, s.Status.Restarts, now)
	if wait > 0 && (next == 0 || wait < next) {
		next = wait
	}
	return probeOutcome{statuses: st, conds: probes.Conditions(s.Spec.Probes, st), restart: restart, next: next}
}

// newer keeps, per probe, whichever status ran last.
func newer(a, b []v1.ProbeStatus) []v1.ProbeStatus {
	out := append([]v1.ProbeStatus(nil), a...)
	for _, x := range b {
		cur := v1.FindProbe(out, x.Name)
		switch {
		case cur == nil:
			out = append(out, x)
		case cur.LastTime == nil || (x.LastTime != nil && !x.LastTime.Before(*cur.LastTime)):
			*cur = x
		}
	}
	return out
}

// runProbe runs one probe once.
func (a *Agent) runProbe(ctx context.Context, rt kri.Runtime, s *v1.Silo, address string, n probes.Named) probes.Outcome {
	limit := probes.RunTimeout(n.Name, n.Probe)
	cctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	p := n.Probe
	timedOut := func() bool { return errors.Is(cctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil }
	switch {
	case p.Exec != nil:
		if !rt.Info().Capabilities.Exec {
			return probes.Outcome{Result: v1.ResultCantRun, Reason: "runtime " + s.Spec.Runtime + " can't exec in a silo"}
		}
		var out bytes.Buffer
		code, err := rt.Exec(cctx, idOf(s), kri.ExecRequest{Command: p.Exec.Command, Stdout: &out, Stderr: &out})
		switch {
		case timedOut():
			return probes.Outcome{Result: v1.ResultFailure, Reason: fmt.Sprintf("timed out after %s", limit)}
		case err != nil:
			return probes.Outcome{Result: v1.ResultCantRun, Reason: tail(err.Error(), 200)}
		case code != 0:
			msg := fmt.Sprintf("exit %d", code)
			if o := tail(out.String(), 200); o != "" {
				msg += ": " + o
			}
			return probes.Outcome{Result: v1.ResultFailure, Reason: msg}
		}
		return probes.Outcome{Result: v1.ResultSuccess, Reason: tail(out.String(), 200)}
	case p.TCP != nil || p.HTTP != nil:
		port := ""
		if p.TCP != nil {
			port = p.TCP.Port
		} else {
			port = p.HTTP.Port
		}
		num, ok := probes.ResolvePort(port, s.Spec)
		if !ok {
			return probes.Outcome{Result: v1.ResultCantRun, Reason: fmt.Sprintf("port %q isn't one of the silo's declared ports", port)}
		}
		if address == "" {
			return probes.Outcome{Result: v1.ResultCantRun, Reason: "the silo has no address its host can reach (runtime " + s.Spec.Runtime + ")"}
		}
		addr := net.JoinHostPort(address, strconv.Itoa(num))
		if p.TCP != nil {
			c, err := a.dial(cctx, "tcp", addr)
			if err != nil {
				if timedOut() {
					return probes.Outcome{Result: v1.ResultFailure, Reason: fmt.Sprintf("dial %s: timed out after %s", addr, limit)}
				}
				return probes.Outcome{Result: v1.ResultFailure, Reason: shortErr(err)}
			}
			_ = c.Close()
			return probes.Outcome{Result: v1.ResultSuccess, Reason: "connected to " + addr}
		}
		return a.httpProbe(cctx, addr, p.HTTP.Path, limit, timedOut)
	}
	return probes.Outcome{Result: v1.ResultCantRun, Reason: "no exec, tcp or http"}
}

func (a *Agent) httpProbe(ctx context.Context, addr, path string, limit time.Duration, timedOut func() bool) probes.Outcome {
	if path == "" {
		path = "/"
	}
	url := "http://" + addr + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return probes.Outcome{Result: v1.ResultCantRun, Reason: err.Error()}
	}
	req.Header.Set("User-Agent", "kevaso-probe")
	hc := &http.Client{
		Transport: &http.Transport{DialContext: a.dial, DisableKeepAlives: true},
		// 3xx passes as it is: the probe asks whether the silo answers, not where it points.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := hc.Do(req)
	if err != nil {
		if timedOut() {
			return probes.Outcome{Result: v1.ResultFailure, Reason: fmt.Sprintf("GET %s: timed out after %s", path, limit)}
		}
		return probes.Outcome{Result: v1.ResultFailure, Reason: shortErr(err)}
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return probes.Outcome{Result: v1.ResultSuccess, Reason: "HTTP " + strconv.Itoa(resp.StatusCode)}
	}
	return probes.Outcome{Result: v1.ResultFailure, Reason: "HTTP " + resp.Status}
}

// shortErr is the end of an error: the part that says what went wrong.
func shortErr(err error) string { return tail(err.Error(), 200) }

// applyProbes writes what a round of probes decided into a silo's status.
func applyProbes(st *v1.SiloStatus, s *v1.Silo, o probeOutcome, now time.Time) {
	st.Probes = o.statuses
	has := map[string]bool{}
	for _, c := range o.conds {
		has[c.Type] = true
		setCond(st, c.Type, c.Status, c.Reason, c.Message, s.Generation, now)
	}
	if !has["StartFailed"] {
		removeCond(st, "StartFailed")
	}
	setDegraded(st, s, now)
}

func removeCond(st *v1.SiloStatus, typ string) {
	out := st.Conditions[:0:0]
	for _, c := range st.Conditions {
		if c.Type != typ {
			out = append(out, c)
		}
	}
	st.Conditions = out
}

// setDegraded is the Degraded condition from both of what can make a silo Degraded: a failing
// liveness probe, and upkeep whose fix didn't help.
func setDegraded(st *v1.SiloStatus, s *v1.Silo, now time.Time) {
	failed := keep.Degraded(st.Upkeep)
	live, msg := probes.Degraded(s.Spec.Probes, st.Probes)
	if live {
		if probes.OnFailure(s.Spec.Probes.Liveness) == v1.OnFailureReport {
			msg += " (onFailure: report: nothing else is done)"
		} else {
			msg += " (onFailure: restart)"
		}
	}
	switch {
	case live && len(failed) > 0:
		setCond(st, "Degraded", meta.ConditionTrue, "LivenessFailing", msg+"; upkeep failed: "+strings.Join(failed, ", "), s.Generation, now)
	case live:
		setCond(st, "Degraded", meta.ConditionTrue, "LivenessFailing", msg, s.Generation, now)
	case len(failed) > 0:
		setCond(st, "Degraded", meta.ConditionTrue, "UpkeepFailed", "upkeep failed: "+strings.Join(failed, ", "), s.Generation, now)
	case meta.FindCondition(st.Conditions, "Degraded") != nil:
		setCond(st, "Degraded", meta.ConditionFalse, "Healthy", "liveness passing (if any) and every upkeep task passes", s.Generation, now)
	}
}

// degradedWanted is whether the silo should be Degraded now (what setDegraded would say).
func degradedWanted(s *v1.Silo, upkeep []v1.UpkeepStatus, ps []v1.ProbeStatus) bool {
	live, _ := probes.Degraded(s.Spec.Probes, ps)
	return live || len(keep.Degraded(upkeep)) > 0
}

// restartForLiveness restarts a silo's workload in place because its liveness probe failed and
// it asked for that (onFailure: restart): stopped, then started again by the next reconcile with
// the same disk and address, init steps per init.when. Recorded first, with its backoff, so a
// crash in between never restarts it twice.
func (a *Agent) restartForLiveness(ctx context.Context, rt kri.Runtime, s *v1.Silo, o probeOutcome) error {
	now := a.now()
	_, why := probes.Degraded(s.Spec.Probes, o.statuses)
	r := probes.Restarted(s.Status.Restarts, now)
	a.log("silo %s/%s: %s: restarting it (onFailure: restart; restart %d)", s.Namespace, s.Name, why, r.Count)
	if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		applyProbes(st, s, o, now)
		st.Restarts = r
		st.Phase = PhaseStarting
		setCond(st, "Ready", meta.ConditionFalse, "LivenessRestart", why+": restarting (restart "+strconv.Itoa(r.Count)+")", s.Generation, now)
	}); err != nil {
		return err
	}
	a.probed.Delete(s.UID)
	return rt.Stop(ctx, idOf(s))
}
