package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/siloset"
)

// setOpts are the flags of kvo scale, reset and protect.
type setOpts struct {
	instances    int
	instancesSet bool
	rolling      bool // reset siloset: every instance, a few at a time
	off          bool // protect: remove the protection
	yes          bool // scale in: yes, delete those instances and their disks
}

// scale: kvo scale siloset NAME --instances N. Scaling in deletes instances and their disks, so
// it says which and needs --yes.
func scale(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 || !o.sets.instancesSet {
		return errors.New("scale needs siloset NAME --instances N (or KIND NAME --replicas N for a defined kind with scale)")
	}
	if k, err := kindOf(o.args[0]); err != nil || k.Kind != "SiloSet" {
		return scaleDefined(ctx, c, o, stdout) // scale.go
	}
	if o.sets.instances < 0 {
		return errors.New("--instances can't be negative")
	}
	ns := defaultNS(o)
	var set v1.SiloSet
	if err := c.Get(ctx, "SiloSet", ns, o.args[1], &set); err != nil {
		return err
	}
	if o.sets.instances < set.Spec.Instances {
		list, err := c.List(ctx, "Silo", ns)
		if err != nil {
			return err
		}
		var insts []*v1.Silo
		for _, item := range list.Items {
			obj, _, err := v1.Decode(item)
			if err != nil {
				continue
			}
			if s, ok := obj.(*v1.Silo); ok && siloset.Owned(&set, s) {
				insts = append(insts, s)
			}
		}
		after := set
		after.Spec.Instances = o.sets.instances
		gone := siloset.Decide(&after, insts).Delete
		if len(gone) > 0 && !o.sets.yes {
			return fmt.Errorf("scaling %s to %d deletes %s and their disks; run again with --yes to go ahead (kvo protect silo NAME keeps one)",
				set.Name, o.sets.instances, strings.Join(gone, ", "))
		}
	}
	set.Spec.Instances = o.sets.instances
	if err := c.Update(ctx, &set); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "siloset/%s scaled to %d\n", set.Name, o.sets.instances)
	return nil
}

// reset: kvo reset silo NAME puts one silo back onto its image (a set's instance: onto the set's
// current image and template); kvo reset siloset NAME --rolling does every instance, a few at a
// time. Stop-first, volumes kept.
func reset(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("reset needs silo NAME, or siloset NAME --rolling")
	}
	k, err := kindOf(o.args[0])
	if err != nil {
		return err
	}
	ns, name := defaultNS(o), o.args[1]
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	switch k.Kind {
	case "Silo":
		var s v1.Silo
		if err := c.Get(ctx, "Silo", ns, name, &s); err != nil {
			return err
		}
		if setName := ownerSet(&s); setName != "" {
			var set v1.SiloSet
			if err := c.Get(ctx, "SiloSet", ns, setName, &set); err == nil {
				i := v1.InstanceIndex(set.Name, s.Name)
				want := set.Instance(i, s.Labels[v1.LabelStandby] == "true")
				s.Spec = want.Spec
				for k, v := range want.Labels {
					if s.Labels == nil {
						s.Labels = map[string]string{}
					}
					s.Labels[k] = v
				}
			}
		}
		s.Spec.Reset = stamp
		if err := c.Update(ctx, &s); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "silo/%s: resetting onto %s (stop-first: it's stopped, its disk made fresh from the image; volumes kept)\n", s.Name, dash(s.Spec.From()))
	case "SiloSet":
		if !o.sets.rolling {
			return errors.New("reset siloset resets every instance: say --rolling (or reset one: kvo reset silo NAME)")
		}
		var set v1.SiloSet
		if err := c.Get(ctx, "SiloSet", ns, name, &set); err != nil {
			return err
		}
		set.Spec.Reset = stamp
		if err := c.Update(ctx, &set); err != nil {
			return err
		}
		unavail, surge := set.Limits()
		_, _ = fmt.Fprintf(stdout, "siloset/%s: resetting every instance onto %s, %d at a time", set.Name, dash(set.InstanceSpec().From()), unavail)
		if surge > 0 {
			_, _ = fmt.Fprintf(stdout, ", %d extra started first", surge)
		}
		_, _ = fmt.Fprintln(stdout, " (kvo get siloset "+set.Name+" -w … or describe it)")
	default:
		return errors.New("reset works on silos and silosets")
	}
	return nil
}

// protect: kvo protect silo NAME [--off]. A protected instance is never removed by scale-in.
func protect(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("protect needs silo NAME [--off]")
	}
	if k, err := kindOf(o.args[0]); err != nil || k.Kind != "Silo" {
		return errors.New("protect works on silos")
	}
	ns := defaultNS(o)
	for attempt := 0; attempt < 5; attempt++ {
		var s v1.Silo
		if err := c.Get(ctx, "Silo", ns, o.args[1], &s); err != nil {
			return err
		}
		if s.Labels == nil {
			s.Labels = map[string]string{}
		}
		if o.sets.off {
			delete(s.Labels, v1.LabelProtected)
		} else {
			s.Labels[v1.LabelProtected] = "true"
		}
		err := c.Update(ctx, &s)
		if client.IsConflict(err) {
			continue
		}
		if err != nil {
			return err
		}
		if o.sets.off {
			_, _ = fmt.Fprintf(stdout, "silo/%s: no longer protected\n", s.Name)
		} else {
			_, _ = fmt.Fprintf(stdout, "silo/%s: protected (scale-in never removes it)\n", s.Name)
		}
		return nil
	}
	return errors.New("silo kept changing; try again")
}
