package restore

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// SettleCommand is the operator command that places a frozen silo on host.
func SettleCommand(namespace, name, host string) string {
	return fmt.Sprintf("kvoadm restore settle %s -n %s --to %s", name, namespace, host)
}

// FreezeMessage names every holder and the command that picks each one.
func FreezeMessage(namespace, name string, holders []string) string {
	h := append([]string{}, holders...)
	sort.Strings(h)
	cmds := make([]string, 0, len(h))
	for _, host := range h {
		cmds = append(cmds, SettleCommand(namespace, name, host))
	}
	return "copies on " + strings.Join(h, ", ") + "; " + strings.Join(cmds, " or ")
}

// DecideSettle is the status a cluster-admin settle writes, or why it is refused.
// host must have reported a copy of s under the gate's history, and s must be frozen
// under that same history. The placement has no handoff and does not follow volumes:
// a handoff is what lets another host delete its disk.
func DecideSettle(g *v1.RestoreGate, s *v1.Silo, host string, hosts []*v1.Host) (v1.SiloStatus, error) {
	if s == nil {
		return v1.SiloStatus{}, fmt.Errorf("no silo")
	}
	if g == nil || g.Spec.History == "" {
		return v1.SiloStatus{}, fmt.Errorf("no restored history is open")
	}
	r := s.Status.Restore
	if r == nil || r.Phase != v1.RestoreFrozen { // a silo that is not frozen is refused
		return v1.SiloStatus{}, fmt.Errorf("%s/%s is not frozen", s.Namespace, s.Name)
	}
	if r.History != g.Spec.History { // a freeze from another history is refused
		return v1.SiloStatus{}, fmt.Errorf("%s/%s is frozen under history %s, not this history %s", s.Namespace, s.Name, r.History, g.Spec.History)
	}
	if ConfirmedOff(g, host) {
		return v1.SiloStatus{}, fmt.Errorf("%s is confirmed off and starts nothing", host)
	}
	var found *v1.Host
	for _, h := range hosts {
		if h != nil && h.Name == host {
			found = h
			break
		}
	}
	if found != nil && found.Status.Copies != nil && found.Status.Copies.Reported && found.Status.Copies.History != g.Spec.History {
		return v1.SiloStatus{}, fmt.Errorf("%s reported under history %s, not this history %s", host, found.Status.Copies.History, g.Spec.History)
	}
	if !reportedThisCopy(found, g, s) { // a host that reported no copy of this silo is refused
		return v1.SiloStatus{}, fmt.Errorf("%s has not reported a copy of %s/%s under this history", host, s.Namespace, s.Name)
	}
	return placeOn(s.Status, g.Spec.History, host), nil
}

func reportedThisCopy(h *v1.Host, g *v1.RestoreGate, s *v1.Silo) bool {
	if h == nil || g == nil || s == nil || h.Status.Copies == nil || !h.Status.Copies.Reported || h.Status.Copies.History != g.Spec.History {
		return false
	}
	for _, c := range h.Status.Copies.Held {
		if c.UID == s.UID && c.Namespace == s.Namespace && c.Name == s.Name && c.UID != "" {
			return true
		}
	}
	return false
}

// placeOn is the one status write: on host, no address, scheduled, no handoff, settled
// for this history, Frozen cleared. Volumes are left as stored.
func placeOn(st v1.SiloStatus, history, host string) v1.SiloStatus {
	st.Host = host
	st.SiloIP = "" // the old address is not the placement's
	st.Phase = "Scheduled"
	st.MovingFrom = "" // no handoff: the other copies stay stopped with their disks
	st.Restore = &v1.SiloRestore{History: history, Phase: v1.RestoreSettled, Holders: []string{host}}
	st.Conditions = dropCondition(st.Conditions, v1.CondFrozen) // Frozen ends in the same write
	return st
}

func dropCondition(in []meta.Condition, typ string) []meta.Condition {
	var out []meta.Condition
	for _, c := range in {
		if c.Type != typ {
			out = append(out, c)
		}
	}
	return out
}

// Account is what init --restore and restore status print once the objects are read.
func Account(g *v1.RestoreGate, hosts []*v1.Host, silos []*v1.Silo) string {
	if g == nil {
		g = &v1.RestoreGate{}
	}
	var unsettled []string
	type frozen struct {
		line string
		cmds []string
	}
	var frozenSilos []frozen
	for _, s := range silos {
		if s == nil || !BlocksPlacement(s, g) {
			continue
		}
		if s.Status.Restore != nil && s.Status.Restore.Phase == v1.RestoreFrozen {
			frozenSilos = append(frozenSilos, frozen{
				line: fmt.Sprintf("%s/%s (copies on %s)", s.Namespace, s.Name, orList(s.Status.Restore.Holders)),
				cmds: settleCommands(s, g),
			})
			continue
		}
		unsettled = append(unsettled, s.Namespace+"/"+s.Name)
	}
	sort.Strings(unsettled)
	sort.Slice(frozenSilos, func(i, j int) bool { return frozenSilos[i].line < frozenSilos[j].line })
	var b strings.Builder
	fmt.Fprintf(&b, "restore: history %s\nhosts that have not reported: %s\nunsettled silos: %s\n",
		g.Spec.History, orList(Unreported(g, hosts)), orList(unsettled))
	if len(frozenSilos) == 0 {
		b.WriteString("frozen silos: none\n")
		return b.String()
	}
	b.WriteString("frozen silos:\n")
	for _, f := range frozenSilos {
		b.WriteString(f.line + "\n")
		for _, cmd := range f.cmds { // one settle command per holder
			b.WriteString(cmd + "\n")
		}
	}
	return b.String()
}

func settleCommands(s *v1.Silo, g *v1.RestoreGate) []string {
	if s.Status.Restore == nil {
		return nil
	}
	var cmds []string
	for _, h := range s.Status.Restore.Holders {
		if ConfirmedOff(g, h) { // a confirmed-off host is skipped: it starts nothing
			continue
		}
		cmds = append(cmds, SettleCommand(s.Namespace, s.Name, h))
	}
	return cmds
}

func orList(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// OtherCopiesRunning is every holder except chosen whose report does not yet say this
// copy is stopped. A confirmed-off holder is skipped: it starts nothing and will not report.
func OtherCopiesRunning(hosts []*v1.Host, g *v1.RestoreGate, namespace, name, uid, chosen string, holders []string) []string {
	byName := map[string]*v1.Host{}
	for _, h := range hosts {
		if h != nil {
			byName[h.Name] = h
		}
	}
	var waiting []string
	for _, h := range holders {
		if h == chosen || ConfirmedOff(g, h) {
			continue
		}
		if !copyStopped(byName[h], g, namespace, name, uid) {
			waiting = append(waiting, h)
		}
	}
	return waiting
}

func copyStopped(h *v1.Host, g *v1.RestoreGate, namespace, name, uid string) bool {
	if h == nil || g == nil || h.Status.Copies == nil || !h.Status.Copies.Reported || h.Status.Copies.History != g.Spec.History {
		return false
	}
	for _, c := range h.Status.Copies.Held {
		if c.Namespace == namespace && c.Name == name && c.UID == uid {
			return !c.Running
		}
	}
	return false
}

// WaitOthers blocks until every holder but chosen reports this copy stopped.
func WaitOthers(ctx context.Context, c *client.Client, namespace, name, uid, chosen string, holders []string) error {
	return waitOthers(ctx, func() ([]*v1.Host, *v1.RestoreGate, error) {
		var g v1.RestoreGate
		if err := c.Get(ctx, "RestoreGate", "", v1.RestoreGateName, &g); err != nil {
			return nil, nil, err
		}
		hosts, err := listHosts(ctx, c)
		return hosts, &g, err
	}, namespace, name, uid, chosen, holders)
}

func waitOthers(ctx context.Context, load func() ([]*v1.Host, *v1.RestoreGate, error), namespace, name, uid, chosen string, holders []string) error {
	for {
		hosts, g, err := load()
		if err != nil {
			return err
		}
		waiting := OtherCopiesRunning(hosts, g, namespace, name, uid, chosen, holders)
		if len(waiting) == 0 { // every other holder's report says that copy is stopped
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s/%s is on %s, and still running on %s", namespace, name, chosen, strings.Join(waiting, ", "))
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func listHosts(ctx context.Context, c *client.Client) ([]*v1.Host, error) {
	l, err := c.List(ctx, "Host", "")
	if err != nil {
		return nil, err
	}
	var out []*v1.Host
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, obj.(*v1.Host))
	}
	return out, nil
}

// SettleCopy asks the API to settle silo on host, then waits until every other holder's
// report says that copy is stopped. The copy already running on host stays running.
func SettleCopy(ctx context.Context, c *client.Client, namespace, name, host string) error {
	var before v1.Silo
	if err := c.Get(ctx, "Silo", namespace, name, &before); err != nil {
		return err
	}
	var holders []string
	if before.Status.Restore != nil {
		holders = append(holders, before.Status.Restore.Holders...)
	}
	path := "/apis/kevaso/v1/namespaces/" + url.PathEscape(namespace) + "/silos/" + url.PathEscape(name) + "/restore-settle"
	var after v1.Silo
	if err := c.Call(ctx, http.MethodPost, path, map[string]string{"to": host}, &after); err != nil {
		return err
	}
	return WaitOthers(ctx, c, namespace, name, before.UID, host, holders)
}
