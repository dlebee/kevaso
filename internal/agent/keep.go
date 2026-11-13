package agent

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/keep"
	"kevaso.com/core/sdk/kri"
)

// keptState is what the agent last decided for one silo's daemons and upkeep.
type keptState struct {
	daemons []v1.DaemonStatus
	upkeep  []v1.UpkeepStatus
}

// upkeepTimeout bounds one upkeep run (a check, a fix, the check again).
const upkeepTimeout = 15 * time.Minute

// keepInside runs a running silo's daemons and upkeep (design §0.5) through the runtime's exec,
// and returns when to look again (0: nothing to keep).
func (a *Agent) keepInside(ctx context.Context, rt kri.Runtime, s *v1.Silo) (time.Duration, error) {
	if len(s.Spec.Daemons) == 0 && len(s.Spec.Upkeep) == 0 && len(s.Status.Daemons) == 0 && len(s.Status.Upkeep) == 0 {
		return 0, nil
	}
	id := idOf(s)
	run := func(ctx context.Context, argv []string) (int, string, error) {
		var out bytes.Buffer
		code, err := rt.Exec(ctx, id, kri.ExecRequest{Command: argv, Stdout: &out, Stderr: &out})
		return code, out.String(), err
	}
	now := a.now()
	var again time.Duration
	soonest := func(d time.Duration) {
		if d > 0 && (again == 0 || d < again) {
			again = d
		}
	}

	// What this agent last decided wins over the silo it read, which can be older than its own
	// last write: otherwise a check would run twice, or a daemon start twice.
	mine, _ := a.kept.Load(s.UID)
	last, _ := mine.(keptState)
	prevD := map[string]v1.DaemonStatus{}
	for _, d := range s.Status.Daemons {
		prevD[d.Name] = d
	}
	for _, d := range last.daemons {
		prevD[d.Name] = d
	}
	var daemons []v1.DaemonStatus
	inSpec := map[string]bool{}
	for _, d := range s.Spec.Daemons {
		inSpec[d.Name] = true
		code, out, err := run(ctx, keep.ProbeCommand(d))
		if err != nil {
			return 0, err
		}
		p := keep.ParseProbe(out)
		if code != 0 {
			p = keep.Probe{Unknown: true}
		}
		if p.Unknown {
			a.log("%s/%s: daemon %s: the probe said %q (exit %d): looking again", s.Namespace, s.Name, d.Name, tail(strings.TrimSpace(out), 200), code)
		}
		st, start, next := keep.DecideDaemon(d, prevD[d.Name], p, now)
		if start {
			if code, out, err := run(ctx, keep.StartCommand(d)); err != nil {
				return 0, err
			} else if code != 0 {
				a.log("%s/%s: daemon %s didn't start: %s", s.Namespace, s.Name, d.Name, tail(out, 200))
			}
		}
		daemons = append(daemons, st)
		soonest(next)
	}
	for name := range prevD {
		if !inSpec[name] { // taken out of the spec: stop it
			if _, _, err := run(ctx, keep.StopCommand(name)); err != nil {
				return 0, err
			}
		}
	}

	prevU := map[string]v1.UpkeepStatus{}
	for _, u := range s.Status.Upkeep {
		prevU[u.Name] = u
	}
	for _, u := range last.upkeep {
		if p, ok := prevU[u.Name]; !ok || p.LastCheck == nil || (u.LastCheck != nil && u.LastCheck.After(*p.LastCheck)) {
			prevU[u.Name] = u
		}
	}
	var upkeep []v1.UpkeepStatus
	for _, u := range s.Spec.Upkeep {
		due, next := keep.Due(u, prevU[u.Name], now)
		if !due {
			upkeep = append(upkeep, prevU[u.Name])
			soonest(next)
			continue
		}
		uctx, cancel := context.WithTimeout(ctx, upkeepTimeout)
		var o keep.Outcome
		var out string
		var err error
		o.Check, out, err = run(uctx, keep.CheckCommand(u))
		if err == nil && o.Check != 0 {
			o.FixRan = true
			o.Fix, out, err = run(uctx, keep.FixCommand(u))
			if err == nil && o.Fix == 0 {
				o.After, out, err = run(uctx, keep.CheckCommand(u))
			}
		}
		cancel()
		if err != nil {
			return 0, err
		}
		if o.Check != 0 && (o.Fix != 0 || o.After != 0) {
			o.Output = tail(strings.TrimSpace(out), 300)
		}
		st := keep.Result(u, prevU[u.Name], o, now)
		if st.State != v1.UpkeepOK {
			a.log("%s/%s: upkeep %q: %s %s", s.Namespace, s.Name, u.Name, st.State, st.Message)
		}
		upkeep = append(upkeep, st)
		_, next = keep.Due(u, st, now)
		soonest(next)
	}

	a.kept.Store(s.UID, keptState{daemons: daemons, upkeep: upkeep})
	if reflect.DeepEqual(daemons, s.Status.Daemons) && reflect.DeepEqual(upkeep, s.Status.Upkeep) &&
		degradedWanted(s, upkeep, s.Status.Probes) == meta.IsTrue(s.Status.Conditions, "Degraded") {
		return again, nil
	}
	return again, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		st.Daemons, st.Upkeep = daemons, upkeep
		setDegraded(st, s, a.now()) // with liveness: both can make it Degraded
	})
}
