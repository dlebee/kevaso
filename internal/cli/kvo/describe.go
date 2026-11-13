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
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func describe(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("describe needs KIND NAME")
	}
	k, err := resolveKind(ctx, c, o.args[0])
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
	if x, ok := obj.(*v1.IP); ok {
		return describeIP(ctx, c, x, stdout)
	}
	if err := describeObject(stdout, obj); err != nil {
		return err
	}
	if s, ok := obj.(*v1.Silo); ok {
		return describeLeases(ctx, c, s, stdout)
	}
	return nil
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
	case *v1.Unstructured:
		kv(0, "Kind", o.Kind+" ("+o.APIVersion+")")
		conds = unstructuredConditions(o)
		lines := describeFields(o)
		tables = append(tables, func() {
			for _, l := range lines {
				_, _ = fmt.Fprintln(tw, l)
			}
		})
	case *v1.Silo:
		kv(0, "Runtime", o.Spec.Runtime)
		img := dash(o.Spec.Image)
		if im := o.Status.Image; im != nil {
			if im.Ref != "" && im.Ref != o.Spec.Image {
				img += " → " + im.Ref
			}
			if im.Running != "" && im.Running != im.Ref {
				img += " (running " + im.Running + ": the update is on its way)"
			}
		}
		kv(0, "Image", img)
		describePull(kv, o)
		if o.Spec.Exclusive {
			kv(0, "Exclusive", "at most one copy ever runs: updates stop-first, no automatic failover")
		}
		if set := ownerSet(o); set != "" {
			kv(0, "SiloSet", set+" (revision "+dash(o.Labels[v1.LabelRevision])+")")
		}
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
		if o.Status.MovingFrom != "" {
			kv(0, "Moving from", o.Status.MovingFrom+" (it stops the silo and lets go first)")
		}
		kv(0, "Movable", dash(o.Status.Movable)+" (onHostLoss: "+o.Policy()+")")
		kv(0, "Silo IP", dash(o.Status.SiloIP))
		st := o.Status.Service
		if sv := o.Spec.Service; sv == nil {
			kv(0, "Service", "none: no name, nothing reachable (a silo IP for its own traffic only)")
		} else {
			name := v1.ServiceName(o)
			if st.Name != "" {
				name += " (" + st.Name + ")"
			}
			kv(0, "Service", name)
			if sv.LoadBalancer != nil {
				lb := sv.LoadBalancer.Class
				if st.LoadBalancerIP != "" {
					lb += " at " + st.LoadBalancerIP
				}
				kv(0, "Load balancer", lb)
			}
		}
		if len(o.Spec.Ports) > 0 {
			tables = append(tables, func() { writeSiloPorts(tw, o) })
		}
		if o.Spec.Service != nil {
			egress := dash(st.EgressIP)
			if src := o.Spec.Network.Egress.Source; src != "" {
				egress += " (" + src + ")"
			}
			kv(0, "Egress IP", egress)
			kv(0, "In and out", st.AddressesLine())
			if st.IP != "" {
				kv(0, "IP", st.IP+" (kvo describe ip "+st.IP+")")
			}
			if len(st.NodePorts) > 0 {
				var ps []string
				for _, p := range st.NodePorts {
					ps = append(ps, fmt.Sprintf("%s %d → host port %d", p.Name, p.Port, p.NodePort))
				}
				kv(0, "Node ports", strings.Join(ps, ", ")+" (from "+strings.Join(st.SourceRanges, ", ")+")")
			}
			if st.Announce {
				kv(0, "Announced", "the load-balancer IP is routed to the silo's host (BGP)")
			}
			tables = append(tables, func() { writeServiceTraffic(tw, o) })
		}
		tables = append(tables, func() { writeProbes(tw, o) })
		if len(o.Spec.Volumes) > 0 {
			got := map[string]v1.VolumeStatus{}
			for _, vs := range o.Status.Volumes {
				got[vs.Name] = vs
			}
			vols := o.Spec.Volumes
			tables = append(tables, func() {
				_, _ = fmt.Fprintln(tw, "Volumes:")
				_, _ = fmt.Fprintln(tw, "  NAME	CLASS	SIZE	MOUNT	WHERE	STATE")
				for _, v := range vols {
					class := v.Class
					if class == "" {
						class = v1.VolumeLocal
					}
					where, state, size := "on the host", "-", dash(v.Size)
					if vs, ok := got[v.Name]; ok {
						if vs.SizeNotEnforced {
							size += " (not enforced)"
						}
						where = dash(vs.Region)
						if vs.Handle != "" {
							where += " #" + vs.Handle
						}
						switch {
						case vs.Mounted:
							state = "mounted on " + vs.AttachedTo
						case vs.AttachedTo != "":
							state = "attached to " + vs.AttachedTo
						case vs.Message != "":
							state = vs.Message
						}
					}
					_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", v.Name, class, size, v.MountPath, where, state)
				}
			})
		}
		kv(0, "Grants", dash(strings.Join(o.Spec.Grants, ", ")))
		// What proves the silo's identity to the broker (design §8.3): today the host vouches.
		kv(0, "Assurance", "host (kevasod on its host vouches for it; no vTPM or confidential VM)")
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
		if len(o.Spec.Daemons) > 0 {
			tables = append(tables, func() {
				_, _ = fmt.Fprintln(tw, "Daemons:")
				_, _ = fmt.Fprintln(tw, "  NAME\tSTATE\tRESTARTS\tLAST EXIT")
				got := map[string]v1.DaemonStatus{}
				for _, st := range o.Status.Daemons {
					got[st.Name] = st
				}
				for _, d := range o.Spec.Daemons {
					st, ok := got[d.Name]
					if !ok {
						st.State = "Pending"
					}
					exit := "-"
					if st.ExitCode != nil {
						exit = fmt.Sprint(*st.ExitCode)
					}
					_, _ = fmt.Fprintf(tw, "  %s\t%s\t%d\t%s\n", d.Name, st.State, st.Restarts, exit)
				}
			})
		}
		if len(o.Spec.Upkeep) > 0 {
			tables = append(tables, func() {
				_, _ = fmt.Fprintln(tw, "Upkeep:")
				_, _ = fmt.Fprintln(tw, "  NAME\tEVERY\tSTATE\tLAST CHECK\tMESSAGE")
				got := map[string]v1.UpkeepStatus{}
				for _, st := range o.Status.Upkeep {
					got[st.Name] = st
				}
				for _, u := range o.Spec.Upkeep {
					st, ok := got[u.Name]
					if !ok {
						st.State = "Pending"
					}
					last := "-"
					if st.LastCheck != nil {
						last = since(*st.LastCheck) + " ago"
					}
					_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", u.Name, u.Every, st.State, last, dash(st.Message))
				}
			})
		}
	case *v1.Host:
		internal := dash(o.Internal())
		if o.Spec.InternalIP == "" && o.Internal() != "" {
			internal += " (the provider's private address)"
		}
		kv(0, "Internal IP", internal)
		kv(0, "External IP", dash(o.External()))
		kv(0, "Mesh IP", dash(o.Status.Network.MeshIP))
		dnsOn := "its silos and the mesh"
		for _, n := range o.Spec.Network.DNS {
			dnsOn += ", its " + n + " IP"
		}
		kv(0, "Names answered on", dnsOn)
		kv(0, "Region", dash(o.Spec.Region))
		kv(0, "Zone", dash(o.Spec.Zone))
		if p := o.Status.Provider; p != nil {
			priv := ""
			if p.PrivateAddress != "" {
				priv = ", private " + p.PrivateAddress
			}
			kv(0, "Provider", fmt.Sprintf("%s (#%s in %s%s)", p.Name, p.ID, p.Region, priv))
		}
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
	case *v1.Ingress:
		kv(0, "Class", o.Spec.IngressClass)
		kv(0, "Hosts", strings.Join(o.Spec.Hosts, ", "))
		switch t := o.Spec.TLS; {
		case t.None:
			kv(0, "TLS", "none: plain HTTP")
		case t.SecretName != "":
			kv(0, "TLS", "your certificate, in secret "+t.SecretName)
		case t.Issuer != "":
			kv(0, "TLS", "a certificate from issuer "+t.Issuer+" ("+dash(o.Status.Certificate)+")")
		default:
			kv(0, "TLS", "a certificate from the cluster's default issuer for the class ("+dash(o.Status.Certificate)+")")
		}
		for i, r := range o.Spec.Rules {
			label := ""
			if i == 0 {
				label = "Routes"
			}
			path := r.Path
			if path == "" {
				path = "/"
			}
			_, _ = fmt.Fprintf(tw, "%s:\t%s → service %s, port %s\n", label, path, r.Service.Name, r.Service.Port)
		}
		kv(0, "Address", dash(o.Status.Address)+"  (point the hosts' DNS here)")
		kv(0, "Certificate", dash(o.Status.Certificate))
		conds = o.Status.Conditions
	case *v1.Certificate:
		kv(0, "Hosts", strings.Join(o.Spec.Hosts, ", "))
		kv(0, "Issuer", o.Spec.Issuer)
		kv(0, "Secret", o.Spec.SecretName)
		if o.Status.NotAfter != nil {
			kv(0, "Valid", o.Status.NotBefore.Local().Format("2006-01-02")+" to "+o.Status.NotAfter.Local().Format("2006-01-02"))
			kv(0, "Renews after", o.Status.RenewAfter.Local().Format("2006-01-02"))
		}
		if o.Status.NextAttempt != nil {
			kv(0, "Next try", fmt.Sprintf("%s (failed %d times in a row)", o.Status.NextAttempt.Local().Format("15:04:05"), o.Status.FailedAttempts))
		}
		conds = o.Status.Conditions
	case *v1.Secret:
		typ := o.Spec.Type
		if typ == "" {
			typ = v1.SecretOpaque
		}
		kv(0, "Type", typ)
		if typ == v1.SecretRegistry {
			kv(0, "Registry", o.Spec.Server+" as "+o.Spec.Username)
			if o.DefaultPull() {
				kv(0, "Default pull", "yes: silos in "+o.Namespace+" pulling from "+o.Spec.Server+" use it unless they name another")
			}
		}
		if o.Status.Version == 0 {
			kv(0, "Value", "none yet")
		} else {
			kv(0, "Value", fmt.Sprintf("version %d, %d bytes, set %s ago", o.Status.Version, o.Status.Size, since(*o.Status.UpdatedAt)))
		}
		if o.Readable() {
			kv(0, "Readable", "yes, with read-value (kvo get secret "+o.Name+" --reveal)")
		} else {
			kv(0, "Readable", "no: write-only, only silos can use it")
		}
		if typ == v1.SecretRegistry {
			kv(0, "Used by", "hosts' agents, to pull the images of silos placed on them: never a silo itself")
		}
		var modes []string
		for _, m := range v1.Deliveries {
			if o.Allows(m) {
				modes = append(modes, m)
			}
		}
		kv(0, "Delivery allowed", strings.Join(modes, ", "))
		if o.Status.PublicKey != "" {
			kv(0, "Public key", o.Status.PublicKey)
		}
		if e := o.Spec.ExpiresAt; e != nil {
			left := time.Until(*e)
			note := "in " + since(time.Now().Add(-left))
			if left < 0 {
				note = "EXPIRED " + since(*e) + " ago"
			} else if left < 7*24*time.Hour {
				note += ": renew it soon (kvo secret set " + o.Name + " --from-file -)"
			}
			kv(0, "Expires", note)
		}
	case *v1.Grant:
		for i, e := range o.Spec.Egress {
			label := ""
			if i == 0 {
				label = "Egress"
			}
			ports := "all ports"
			if len(e.Ports) > 0 {
				ports = "port " + strings.Join(e.Ports, ",")
			}
			protos := "tcp"
			if len(e.Protocols) > 0 {
				protos = strings.Join(e.Protocols, "+")
			}
			how := "host firewall"
			if pe, err := e.Parse(); err == nil && pe.Host != "" {
				how, ports = "egress gate, by TLS name", "port "+portList(pe.Ports)
			}
			_, _ = fmt.Fprintf(tw, "%s:\t%s %s %s (%s)\n", label, protos, e.To, ports, how)
		}
		for i, sec := range o.Spec.Secrets {
			label := ""
			if i == 0 {
				label = "Secrets"
			}
			var how string
			switch sec.Delivery() {
			case v1.DeliverInject:
				t := sec.To
				h, f := t.Header, t.Format
				if h == "" {
					h = "Authorization"
				}
				if f == "" {
					f = "Bearer {{value}}"
				}
				how = fmt.Sprintf("tier 2, injection: the egress gate adds %s: %s for %s; never in the silo", h, f, t.Host)
			case v1.DeliverBroker:
				how = "tier 4, broker: the silo fetches it when needed (curl -fsS -H '" + v1.EndpointHeader + ": 1' http://" + v1.EndpointAddress + "/v1/secrets/" + sec.Name + ")"
			case v1.DeliverFile:
				path := sec.Path
				if path == "" {
					path = "/run/secrets/" + sec.Name
				}
				how = "tier 4, file: " + path + " (tmpfs, written by the host, rewritten on rotation)"
			case v1.DeliverEnv:
				how = "tier 4, env " + envName(sec) + " — FLAGGED: leaks into child processes, dumps, logs and an agent's context"
			}
			_, _ = fmt.Fprintf(tw, "%s:\t%s: %s\n", label, sec.Name, how)
		}
		if op := o.Spec.Operations; op != nil && op.Sign != nil {
			p := ""
			if op.Sign.SlashingProtection {
				p = ", with slashing protection"
			}
			kv(0, "Operations", "tier 3, sign with "+op.Sign.KeyRef+p+": the key never leaves Kevaso")
		}
		if rq := o.Spec.Requires; rq != nil && rq.Assurance != "" && rq.Assurance != v1.AssuranceHost {
			kv(0, "Requires", rq.Assurance+" assurance: no silo can have it yet (only host), so the broker refuses")
		}
	case *v1.SiloSet:
		conds = o.Status.Conditions
		kv(0, "Image", dash(o.InstanceSpec().Image))
		kv(0, "Runtime", o.Spec.Template.Runtime)
		kv(0, "Instances", fmt.Sprintf("%d wanted, %d ready, %d on revision %s", o.Spec.Instances, o.Status.Ready, o.Status.Updated, dash(o.Status.Revision)))
		if o.Spec.Standby > 0 || o.Status.Standby > 0 {
			kv(0, "Standby", fmt.Sprintf("%d wanted, %d there", o.Spec.Standby, o.Status.Standby))
		}
		unavail, surge := o.Limits()
		policy := o.Spec.UpgradePolicy
		if policy == "" {
			policy = v1.UpgradeManual
		}
		how := fmt.Sprintf("%s; at most %d not ready at a time", policy, unavail)
		if surge > 0 {
			how += fmt.Sprintf(", %d extra started first", surge)
		}
		if o.Spec.Template.Exclusive {
			how += "; exclusive: one at a time, stop-first"
		}
		kv(0, "Upgrades", how)
		scaleIn := o.Spec.ScaleInPolicy
		if scaleIn == "" {
			scaleIn = v1.NewestFirst
		}
		kv(0, "Scale-in", scaleIn+" (not ready ones first; protected ones never)")
		if o.Spec.Spread != "" {
			kv(0, "Spread", "by "+o.Spec.Spread)
		}
	case *v1.Service:
		conds = o.Status.Conditions
		typ := o.Spec.Type
		if typ == "" {
			typ = v1.ServiceClusterIP
		}
		if o.Spec.LoadBalancerClass != "" {
			typ += " (" + o.Spec.LoadBalancerClass + ")"
		}
		kv(0, "Type", typ)
		kv(0, "Selector", pairs(o.Spec.Selector))
		kv(0, "Name", dash(o.Status.Name))
		kv(0, "Cluster IP", dash(o.Status.ClusterIP))
		if o.Spec.Type == v1.ServiceLoadBalancer {
			kv(0, "Load-balancer IP", dash(o.Status.LoadBalancerIP))
		}
		nps := map[string]int{}
		for _, np := range o.Status.NodePorts {
			nps[np.Name] = np.NodePort
		}
		var ps []string
		for _, p := range o.Spec.Ports {
			proto, target := p.Protocol, p.TargetPort
			if proto == "" {
				proto = "TCP"
			}
			if target == "" {
				target = p.Name
			}
			x := fmt.Sprintf("%s %d/%s → each silo's port %s", p.Name, p.Port, proto, target)
			if np := nps[p.Name]; np > 0 {
				x += fmt.Sprintf(" (node port %d)", np)
			}
			ps = append(ps, x)
		}
		kv(0, "Ports", strings.Join(ps, ", "))
		rw := o.Spec.RouteWhen
		if rw == "" {
			rw = "not stated (running, for silos without a readiness probe)"
		}
		kv(0, "Route when", rw)
		eps, held := o.Status.Endpoints, o.Status.Held
		tables = append(tables, func() {
			_, _ = fmt.Fprintf(tw, "Endpoints:\t%d routed, %d held\n", len(eps), len(held))
			if len(eps)+len(held) > 0 {
				_, _ = fmt.Fprintln(tw, "  SILO\tHOST\tSILO IP\tPORTS\tTRAFFIC")
				row := func(ep v1.ServiceEndpoint, state string) {
					var tp []string
					for _, p := range ep.Ports {
						tp = append(tp, fmt.Sprintf("%s→%d", p.Name, p.NodePort))
					}
					_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", ep.Silo, ep.Host, ep.SiloIP, strings.Join(tp, ","), state)
				}
				for _, ep := range eps {
					row(ep, "routed")
				}
				for _, ep := range held {
					row(ep, heldText(ep))
				}
			}
		})
	case *v1.Image:
		vs := o.Spec.Versions
		tables = append(tables, func() {
			_, _ = fmt.Fprintln(tw, "Versions:")
			_, _ = fmt.Fprintln(tw, "  NAME\tDISK")
			for _, v := range vs {
				_, _ = fmt.Fprintf(tw, "  %s\t%s\n", v.Name, diskOf(v))
			}
		})
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

func portList(ps []v1.PortRange) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, ",")
}

// envName is the variable a secret delivered as env gets.
func envName(sec v1.GrantSecret) string {
	if sec.Env != "" {
		return sec.Env
	}
	return strings.ToUpper(strings.ReplaceAll(sec.Name, "-", "_"))
}

func ownerSet(s *v1.Silo) string {
	for _, r := range s.OwnerReferences {
		if r.Kind == "SiloSet" && r.Controller {
			return r.Name
		}
	}
	return ""
}
