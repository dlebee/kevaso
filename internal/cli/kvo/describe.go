package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func describe(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("describe needs KIND NAME")
	}
	k, err := kindOf(o.args[0])
	if err != nil {
		return err
	}
	ns := ""
	if k.Scope == v1.Namespaced {
		ns = defaultNS(o)
	}
	obj := k.New()
	if err := c.Get(ctx, k.Kind, ns, o.args[1], obj); err != nil {
		return err
	}
	return describeObject(stdout, obj)
}

// describeObject writes an object for people: what it is, what it wants, how it's doing and why.
func describeObject(w io.Writer, obj meta.Object) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	kv := func(indent int, k string, v any) {
		_, _ = fmt.Fprintf(tw, "%s%s:\t%v\n", strings.Repeat("  ", indent), k, v)
	}
	m := obj.GetObjectMeta()
	kv(0, "Name", m.Name)
	if m.Namespace != "" {
		kv(0, "Namespace", m.Namespace)
	}
	kv(0, "Labels", pairs(m.Labels))
	if m.CreationTimestamp != nil {
		kv(0, "Created", fmt.Sprintf("%s (%s ago)", m.CreationTimestamp.Local().Format("2006-01-02 15:04:05"), since(*m.CreationTimestamp)))
	}
	if m.DeletionTimestamp != nil {
		kv(0, "Deleting", fmt.Sprintf("since %s ago, waiting on %s", since(*m.DeletionTimestamp), dash(strings.Join(m.Finalizers, ", "))))
	}
	var conds []meta.Condition
	var tables []func()
	switch o := obj.(type) {
	case *v1.Silo:
		kv(0, "Runtime", o.Spec.Runtime)
		kv(0, "Image", dash(o.Spec.Image))
		kv(0, "Resources", fmt.Sprintf("%d CPU, %s memory", o.Spec.Resources.CPU, dash(o.Spec.Resources.Memory)))
		disk := dash(o.Spec.Disk.Size)
		if o.Spec.Disk.Class != "" {
			disk += " (" + o.Spec.Disk.Class + ")"
		}
		kv(0, "Disk", disk)
		if p := o.Spec.Placement; p.Region != "" || p.Zone != "" {
			kv(0, "Placement", "region="+dash(p.Region)+" zone="+dash(p.Zone))
		}
		if len(o.Spec.Placement.HostSelector) > 0 {
			kv(0, "Host selector", pairs(o.Spec.Placement.HostSelector))
		}
		if len(o.Spec.Tolerations) > 0 {
			var ts []string
			for _, t := range o.Spec.Tolerations {
				ts = append(ts, fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect))
			}
			kv(0, "Tolerations", strings.Join(ts, ", "))
		}
		kv(0, "Phase", dash(o.Status.Phase))
		kv(0, "Host", dash(o.Status.Host))
		kv(0, "Address", dash(o.Status.Address))
		conds = o.Status.Conditions
		if o.Spec.Init != nil && len(o.Spec.Init.Steps) > 0 {
			tables = append(tables, func() {
				_, _ = fmt.Fprintln(tw, "Init steps:")
				_, _ = fmt.Fprintln(tw, "  NAME\tSTATE\tEXIT\tDURATION")
				got := map[string]v1.StepStatus{}
				for _, st := range o.Status.Init {
					got[st.Name] = st
				}
				for _, step := range o.Spec.Init.Steps {
					st, ok := got[step.Name]
					if !ok {
						st = v1.StepStatus{State: "Pending"}
					}
					exit := "-"
					if st.ExitCode != nil {
						exit = fmt.Sprint(*st.ExitCode)
					}
					_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", step.Name, st.State, exit, dash(st.Duration))
				}
			})
		}
	case *v1.Host:
		kv(0, "Address", o.Spec.Address)
		kv(0, "Region", dash(o.Spec.Region))
		kv(0, "Zone", dash(o.Spec.Zone))
		if o.Spec.Unschedulable {
			kv(0, "Schedulable", "no (cordoned)")
		}
		var comps []string
		if o.Spec.Components.ControlPlane != nil {
			comps = append(comps, "control-plane")
		}
		if o.Spec.Components.Worker != nil {
			comps = append(comps, "worker")
		}
		kv(0, "Components", dash(strings.Join(comps, ", ")))
		if wk := o.Spec.Components.Worker; wk != nil {
			kv(0, "Worker labels", pairs(wk.Labels))
			var ts []string
			for _, t := range wk.Taints {
				ts = append(ts, fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect))
			}
			kv(0, "Taints", dash(strings.Join(ts, ", ")))
			a := o.Status.Allocatable
			kv(0, "Allocatable", fmt.Sprintf("%d CPU, %s memory", a.CPU, dash(a.Memory)))
			tables = append(tables, func() {
				_, _ = fmt.Fprintln(tw, "Runtimes:")
				_, _ = fmt.Fprintln(tw, "  NAME\tSTATE\tVERSION\tMESSAGE")
				for _, r := range wk.Runtimes {
					st, ok := o.Status.Runtimes[r.Name]
					if !ok {
						st = v1.RuntimeStatus{State: "-"}
					}
					_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", r.Name, st.State, dash(st.Version), dash(st.Message))
				}
			})
		}
		if hb := o.Status.LastHeartbeat; hb != nil {
			kv(0, "Last heartbeat", since(*hb)+" ago")
		}
		conds = o.Status.Conditions
	case *v1.Namespace:
		kv(0, "Status", dash(o.Status.Phase))
	}
	for _, t := range tables {
		t()
	}
	if len(conds) > 0 {
		_, _ = fmt.Fprintln(tw, "Conditions:")
		_, _ = fmt.Fprintln(tw, "  TYPE\tSTATUS\tREASON\tSINCE\tMESSAGE")
		for _, cd := range conds {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", cd.Type, cd.Status, dash(cd.Reason), since(cd.LastTransitionTime), dash(cd.Message))
		}
	}
	return tw.Flush()
}

func pairs(m map[string]string) string {
	if len(m) == 0 {
		return "-"
	}
	var out []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		out = append(out, k+"="+m[k])
	}
	return strings.Join(out, ", ")
}
