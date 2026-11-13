package agent

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// A mount-reach volume (juicefs) whose backend is down doesn't fail: every call into it waits until
// the backend is back (research E029: a JuiceFS mount whose metadata database is down). The silo's
// processes wait with it and the silo looks hung, so the agent looks at each such volume's folder
// now and then, and says on the silo when one stops answering: the VolumesResponding condition.

// DefaultProbeTimeout is how long a volume's folder may take to answer before the silo's status
// says it isn't answering (Agent.ProbeTimeout).
const DefaultProbeTimeout = 5 * time.Second

// probeWait is how long a reconcile waits for a probe it started, a fifth of the timeout (a probe
// still going is looked at again on the next pass, never started twice).
func (a *Agent) probeWait() time.Duration { return a.probeTimeout() / 5 }

// DefaultProbeEvery is how often a running silo with mount-reach volumes is looked at again
// (Agent.ProbeEvery).
const DefaultProbeEvery = 10 * time.Second

func (a *Agent) probeTimeout() time.Duration {
	if a.ProbeTimeout > 0 {
		return a.ProbeTimeout
	}
	return DefaultProbeTimeout
}

func (a *Agent) probeEvery() time.Duration {
	if a.ProbeEvery > 0 {
		return a.ProbeEvery
	}
	return DefaultProbeEvery
}

// probeName is what a probe looks up in the volume's folder: a name nobody uses, so the lookup
// goes to the file system's daemon (a cached answer for the folder itself wouldn't).
const probeName = ".kevaso-probe"

type probe struct {
	started time.Time
	done    chan struct{}
	err     error // set before done is closed
}

// defaultProbe looks up a name in dir: an answer, even "no such file", means it's answering.
func defaultProbe(dir string) error {
	_, err := os.Lstat(path.Join(dir, probeName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// mountVolumeDirs are the folders of the silo's mount-reach volumes on this host, by volume name.
func (a *Agent) mountVolumeDirs(s *v1.Silo) map[string]string {
	dirs := map[string]string{}
	for _, v := range s.Spec.Volumes {
		if v.Class == "" || v.Class == v1.VolumeLocal {
			continue
		}
		if _, ok := a.nodeFor(v.Class); ok {
			dirs[v.Name] = a.VolumePath(s.UID, v.Name)
		}
	}
	return dirs
}

// trouble is what a volume's probe found wrong: it hasn't answered (hung), or it answered with an
// error other than "no such file" (a JuiceFS client gives up after its retries and fails calls).
type trouble struct {
	hung bool
	err  string
}

// probeVolumes looks at each of the silo's mount-reach volumes: bad are the ones whose folder has
// not answered for the probe timeout, or answered with an error; pending says a probe is still going.
// While a probe is going (and not yet late), a volume keeps what the last one found.
func (a *Agent) probeVolumes(dirs map[string]string) (bad map[string]trouble, pending bool) {
	look := a.Probe
	if look == nil {
		look = defaultProbe
	}
	bad = map[string]trouble{}
	for name, dir := range dirs {
		found, known := a.probeOnce(dir, look)
		if !known {
			pending = true
			if o, ok := a.probeSaid.Load(dir); ok {
				found = o.(trouble)
			}
		}
		a.probeSaid.Store(dir, found)
		if found.hung || found.err != "" {
			bad[name] = found
		}
	}
	return bad, pending
}

// probeOnce is what the folder's probe says now: known is false while it's going and not yet late.
// A finished probe's answer is taken and a new one started (never two at once for one folder).
func (a *Agent) probeOnce(dir string, look func(string) error) (found trouble, known bool) {
	if o, ok := a.probes.Load(dir); ok {
		old := o.(*probe)
		select {
		case <-old.done:
			a.probes.CompareAndDelete(dir, old)
			if old.err != nil {
				found, known = trouble{err: old.err.Error()}, true
			} else {
				found, known = trouble{}, true
			}
		default:
			if a.Clock.Now().Sub(old.started) >= a.probeTimeout() {
				return trouble{hung: true}, true
			}
			return trouble{}, false
		}
	}
	p := &probe{started: a.Clock.Now(), done: make(chan struct{})}
	if _, loaded := a.probes.LoadOrStore(dir, p); loaded {
		return found, known // another pass started one just now
	}
	go func() {
		p.err = look(dir)
		close(p.done)
	}()
	select {
	case <-p.done:
		a.probes.CompareAndDelete(dir, p)
		if p.err != nil {
			return trouble{err: p.err.Error()}, true
		}
		return trouble{}, true
	case <-time.After(a.probeWait()):
		return found, known
	}
}

// volumesResponding sets the VolumesResponding condition on a running silo with mount-reach volumes.
func (a *Agent) volumesResponding(s *v1.Silo, st *v1.SiloStatus, bad map[string]trouble, dirs map[string]string) {
	if len(dirs) == 0 {
		return
	}
	if len(bad) == 0 {
		if c := meta.FindCondition(st.Conditions, "VolumesResponding"); c == nil || c.Status != meta.ConditionTrue {
			setCond(st, "VolumesResponding", meta.ConditionTrue, "Answering", "its volumes answer", s.Generation, a.now())
		}
		return
	}
	classes := map[string]string{}
	for _, v := range s.Spec.Volumes {
		classes[v.Name] = v.Class
	}
	var names []string
	reason := "Failing"
	for n, tr := range bad {
		what := n + " (" + classes[n] + ")"
		if tr.hung {
			reason = "NotAnswering"
			what += " hasn't answered in " + a.probeTimeout().String()
		} else {
			what += " fails: " + tr.err
		}
		names = append(names, what)
	}
	sort.Strings(names)
	setCond(st, "VolumesResponding", meta.ConditionFalse, reason,
		"volume "+strings.Join(names, "; volume ")+
			". The storage behind it may be down (for juicefs, its metadata database): I/O in the silo waits for it, and fails once its client gives up",
		s.Generation, a.now())
}
