package worker

import (
	"context"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
)

// K-009, K-036, the load. The generator never writes what nft refuses (kni.Generate), and leaves
// out, with a report, what it can't express. Should a table still be rejected (an nft too old for
// a rule, a bug), the kernel keeps the last one it took (nft -f is one transaction), the Host says
// so (condition SiloFirewall), and the load is tried again with a growing pause, on top of every
// change; nothing waits for the next change or the minute's repair.

// Conditions the network loop writes.
const (
	// CondSiloFirewall (on the Host): whether the silo firewall the API asks for is loaded.
	CondSiloFirewall = "SiloFirewall"
	// CondPortRules (on a Silo): entries of its ports the firewall can't express, left out.
	CondPortRules = "PortRules"
)

// firewall loads rulesets and remembers how that went.
type firewall struct {
	apply func(context.Context, string) error
	last  string // the text last loaded
	err   error  // the last load's refusal (nil: the last load, or none tried, went through)
	fails int
}

// retryAfter is the pause before trying a refused table again.
func (f *firewall) retryAfter() time.Duration {
	d := 2 * time.Second << min(f.fails-1, 5)
	return min(d, time.Minute)
}

// load loads text unless it is what's loaded. loaded: it went through now.
func (f *firewall) load(ctx context.Context, text string) (loaded bool, err error) {
	if text == f.last && f.err == nil {
		return false, nil
	}
	if err := f.apply(ctx, text); err != nil {
		f.err = err
		f.fails++
		return false, err
	}
	f.last, f.err, f.fails = text, nil, 0
	return true, nil
}

// hostFirewallCondition is the Host's SiloFirewall condition for how the last load went.
func hostFirewallCondition(err error, problems []kni.Problem) meta.Condition {
	if err != nil {
		return meta.Condition{Type: CondSiloFirewall, Status: meta.ConditionFalse, Reason: "Rejected",
			Message: clip("nft refused the silo firewall; the last one it took stays in force and the load is retried: " + err.Error())}
	}
	var host []string
	for _, p := range problems {
		if p.Kind != "Silo" {
			host = append(host, p.Kind+" "+p.Owner+": "+p.String())
		}
	}
	sort.Strings(host)
	if len(host) > 0 {
		return meta.Condition{Type: CondSiloFirewall, Status: meta.ConditionTrue, Reason: "LoadedWithEntriesLeftOut",
			Message: clip("loaded; left out (they open nothing): " + strings.Join(host, "; "))}
	}
	return meta.Condition{Type: CondSiloFirewall, Status: meta.ConditionTrue, Reason: "Loaded"}
}

// siloProblems are the problems of each silo, as a PortRules message (sorted).
func siloProblems(problems []kni.Problem) map[string]string {
	by := map[string][]string{}
	for _, p := range problems {
		if p.Kind == "Silo" {
			by[p.Owner] = append(by[p.Owner], p.String())
		}
	}
	out := map[string]string{}
	for k, l := range by {
		sort.Strings(l)
		out[k] = clip("left out of the firewall, so closed: " + strings.Join(l, "; "))
	}
	return out
}

// clip keeps a status message short and on one line.
func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 1000 {
		s = s[:1000] + "…"
	}
	return s
}

// reportPortRules puts each local silo's PortRules condition in line with msgs (key → message,
// absent: none), writing only the silos whose condition changes.
func reportPortRules(ctx context.Context, c *client.Client, hostName string, silos []*v1.Silo, msgs map[string]string, now time.Time) {
	for _, s := range silos {
		if s.Status.Host != hostName || s.DeletionTimestamp != nil {
			continue
		}
		msg, bad := msgs[s.Namespace+"/"+s.Name]
		cur := meta.FindCondition(s.Status.Conditions, CondPortRules)
		if (!bad && cur == nil) || (bad && cur != nil && cur.Message == msg && cur.Status == meta.ConditionFalse) {
			continue
		}
		for attempt := 0; attempt < 3; attempt++ {
			var fresh v1.Silo
			if err := c.Get(ctx, "Silo", s.Namespace, s.Name, &fresh); err != nil {
				break
			}
			if bad {
				meta.SetCondition(&fresh.Status.Conditions, meta.Condition{Type: CondPortRules, Status: meta.ConditionFalse, Reason: "LeftOut", Message: msg, ObservedGeneration: fresh.Generation}, now)
			} else {
				var keep []meta.Condition
				for _, x := range fresh.Status.Conditions {
					if x.Type != CondPortRules {
						keep = append(keep, x)
					}
				}
				fresh.Status.Conditions = keep
			}
			if err := c.UpdateStatus(ctx, &fresh); !client.IsConflict(err) {
				break
			}
		}
	}
}

// reportHost writes the Host's SiloFirewall condition when it differs from what it says.
func reportHost(ctx context.Context, c *client.Client, hostName string, me *v1.Host, cond meta.Condition, now time.Time) {
	if me != nil {
		if cur := meta.FindCondition(me.Status.Conditions, cond.Type); cur != nil && cur.Status == cond.Status && cur.Reason == cond.Reason && cur.Message == cond.Message {
			return
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", hostName, &h); err != nil {
			return
		}
		meta.SetCondition(&h.Status.Conditions, cond, now)
		if err := c.UpdateStatus(ctx, &h); !client.IsConflict(err) {
			return
		}
	}
}
