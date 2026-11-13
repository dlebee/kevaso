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
const DefaultProbeTimeout = 10 * time.Second

// probeWait is how long a reconcile waits for a probe it started (a probe still going is looked
// at again on the next pass, never started twice).
var probeWait = 2 * time.Second

// DefaultProbeEvery is how often a running silo with mount-reach volumes is looked at again
// (Agent.ProbeEvery).
const DefaultProbeEvery = 15 * time.Second

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

// probeVolumes looks at each of the silo's mount-reach volumes: stuck are the ones whose folder has
// not answered for the probe timeout (with how long), and pending says a probe is still going.
func (a *Agent) probeVolumes(dirs map[string]string) (stuck map[string]time.Duration, pending bool) {
	look := a.Probe
	if look == nil {
		look = defaultProbe
	}
	stuck = map[string]time.Duration{}
	for name, dir := range dirs {
		p := &probe{started: a.Clock.Now(), done: make(chan struct{})}
		if o, loaded := a.probes.LoadOrStore(dir, p); loaded {
			old := o.(*probe)
			select {
			case <-old.done: // the last one answered: look again
				a.probes.CompareAndDelete(dir, old)
				if _, loaded := a.probes.LoadOrStore(dir, p); loaded {
					continue // another pass started one just now
				}
			default:
				if d := a.Clock.Now().Sub(old.started); d >= a.probeTimeout() {
					stuck[name] = d
				} else {
					pending = true
				}
				continue
			}
		}
		go func() {
			_ = look(dir) // an error is an answer too: only silence is "not answering"
			close(p.done)
		}()
		select {
		case <-p.done:
		case <-time.After(min(probeWait, a.probeTimeout())):
			pending = true
		}
	}
	return stuck, pending
}

// volumesResponding sets the VolumesResponding condition on a running silo with mount-reach volumes.
func (a *Agent) volumesResponding(s *v1.Silo, st *v1.SiloStatus, stuck map[string]time.Duration, dirs map[string]string) {
	if len(dirs) == 0 {
		return
	}
	if len(stuck) == 0 {
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
	for n := range stuck {
		names = append(names, n+" ("+classes[n]+")")
	}
	sort.Strings(names)
	setCond(st, "VolumesResponding", meta.ConditionFalse, "NotAnswering",
		"volume "+strings.Join(names, ", ")+" hasn't answered in "+a.probeTimeout().String()+
			": the storage behind it may be down (for juicefs, its metadata database); I/O in the silo waits, and goes on when it's back",
		s.Generation, a.now())
}
