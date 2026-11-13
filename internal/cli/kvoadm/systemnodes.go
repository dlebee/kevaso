package kvoadm

// More than one system node (design §3, ADR 0006):
//
//	kvoadm store migrate [USER@]ADDRESS --ssh-key PATH            the first control plane onto etcd, peers on
//	kvoadm host add [USER@]ADDRESS --install control-plane [--state-only] …   a second, third system node
//	kvoadm host install HOST control-plane [--state-only] --ssh-key PATH      an existing host becomes one
//	kvoadm host uninstall HOST control-plane | remove HOST      membership first, never below a majority
//
// A cluster on SQLite isn't switched by host add: switching restarts the only API server (every
// watch re-lists) and needs SSH to that machine, which host add doesn't have. It's one visible
// step, `kvoadm store migrate`, and host add says so.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/etcd"
	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/sshboot"
)

// roleSystemNode is the join-token role of a new system node (apiserver.RoleSystemNode).
const roleSystemNode = "system-node"

// JoinReady says whether a cluster can take another system node now (pure): every control plane
// keeps its state in etcd with a peer listener, and no member is mid-join.
func JoinReady(hosts []v1.Host) error {
	n := 0
	for _, h := range hosts {
		if h.Spec.Components.ControlPlane == nil {
			continue
		}
		cp := h.Status.ControlPlane
		if cp == nil || cp.Store == "" {
			continue // declared, not reporting yet: the join itself decides
		}
		n++
		if cp.Store != "etcd" {
			return fmt.Errorf("the cluster keeps its state in SQLite on %s: switch it to etcd first, once:\n    kvoadm store migrate %s --ssh-key PATH\n(the API restarts once; silos keep running)", h.Name, sshAddress(&h))
		}
		if cp.PeerURL == "" {
			return fmt.Errorf("%s's etcd member listens for no peers: run kvoadm store migrate %s --ssh-key PATH (it adds the peer listener)", h.Name, sshAddress(&h))
		}
		if cp.Member == "learner" {
			return fmt.Errorf("%s is still joining (a learner): one system node joins at a time", h.Name)
		}
	}
	if n == 0 {
		return errors.New("no control plane reports its store yet: is the cluster up (kvoadm host list)?")
	}
	return nil
}

// membersFromHosts is the etcd membership as the Hosts show it (the leader writes it there).
func membersFromHosts(hosts []v1.Host, now time.Time, lease time.Duration) []etcd.Member {
	var ms []etcd.Member
	for i, h := range hosts {
		cp := h.Status.ControlPlane
		if cp == nil || cp.Member == "" {
			continue
		}
		ms = append(ms, etcd.Member{ID: uint64(i + 1), Name: h.Name, Learner: cp.Member == "learner"})
	}
	return etcd.Judge(ms, hosts, now, lease)
}

// RemovalCheck says whether host can stop being a system node now (pure): the store decision
// (etcd.NextStep) must remove it without losing the healthy majority, and a full system node must
// stay to serve the API.
func RemovalCheck(hosts []v1.Host, name string, now time.Time, lease time.Duration) error {
	var target *v1.Host
	full := 0
	var rest []v1.Host
	for i := range hosts {
		h := hosts[i]
		if h.Name == name {
			target = &hosts[i]
			continue
		}
		rest = append(rest, h)
		if cp := h.Spec.Components.ControlPlane; cp != nil && !cp.StateOnly {
			full++
		}
	}
	if target == nil || target.Spec.Components.ControlPlane == nil {
		return fmt.Errorf("%s isn't a system node", name)
	}
	if !target.Spec.Components.ControlPlane.StateOnly && full == 0 {
		return fmt.Errorf("%s is the last system node serving the API: the cluster would have no control plane", name)
	}
	ms := membersFromHosts(hosts, now, lease)
	isMember := false
	for _, m := range ms {
		isMember = isMember || m.Name == name
	}
	if !isMember {
		return nil // not in the store (never joined, or already removed)
	}
	step := etcd.NextStep(etcd.DesiredMembers(rest), ms)
	if step.Action == etcd.Remove && step.Name == name {
		return nil
	}
	if step.Action == etcd.Blocked {
		return fmt.Errorf("removing %s now would lose the store's healthy majority (%s): add or repair a system node first", name, step.Reason)
	}
	return fmt.Errorf("another membership change comes first (%s %s: %s): try again when it's done", step.Action, step.Name, step.Reason)
}

// SystemNodeUnit is the systemd unit of a joining system node (pure). servers are control planes
// it may ask to join; worker adds the worker component (HA compact).
func SystemNodeUnit(o HostAddOptions, servers []string, stateOnly, worker bool) string {
	addr := o.Reach()
	args := append(append([]string{"control-plane", "--name", o.Name}, o.ipArgs()...), "--cluster", o.Cluster,
		"--store", "etcd", "--etcd-peer-listen", net.JoinHostPort(addr, etcd.DefaultPeerPort),
		"--join", strings.Join(servers, ","), "--join-token-file", "/etc/kevaso/join-token", "--ca-file", "/etc/kevaso/ca.crt")
	if o.ClusterDNS != "" {
		args = append(args, "--cluster-dns", o.ClusterDNS)
	}
	if stateOnly {
		args = append(args, "--state-only", "--mesh=false")
	} else if worker {
		args = append(args, workerArgs(o.InitOptions)...)
	}
	desc := "Kevaso control plane (kevasod)"
	if stateOnly {
		desc = "Kevaso light system node: store member only (kevasod)"
	}
	return `[Unit]
Description=` + desc + `
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/kevasod ` + strings.Join(args, " ") + `
Restart=always
RestartSec=2
RuntimeDirectory=kevaso
RuntimeDirectoryMode=0700
StateDirectory=kevaso
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`
}

// WithEtcd rewrites a control-plane unit to keep its state in etcd with a peer listener on
// peerListen (pure). It says whether anything changed.
func WithEtcd(unit, peerListen string) (string, bool, error) {
	lines := strings.Split(unit, "\n")
	for i, l := range lines {
		rest, ok := strings.CutPrefix(l, "ExecStart=/usr/local/bin/kevasod ")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 || f[0] != "control-plane" {
			return "", false, errors.New("this host's kevasod isn't a control plane")
		}
		var keep []string
		for j := 0; j < len(f); j++ {
			switch f[j] {
			case "--store", "--etcd-peer-listen":
				j++
				continue
			}
			if strings.HasPrefix(f[j], "--store=") || strings.HasPrefix(f[j], "--etcd-peer-listen=") {
				continue
			}
			keep = append(keep, f[j])
		}
		keep = append(keep, "--store", "etcd", "--etcd-peer-listen", peerListen)
		next := "ExecStart=/usr/local/bin/kevasod " + strings.Join(keep, " ")
		changed := next != l
		lines[i] = next
		return strings.Join(lines, "\n"), changed, nil
	}
	return "", false, errors.New("no kevasod ExecStart in the unit: is the control plane installed here (kvoadm init)?")
}

func listHosts(ctx context.Context, c *client.Client) ([]v1.Host, error) {
	l, err := c.List(ctx, "Host", "")
	if err != nil {
		return nil, err
	}
	var out []v1.Host
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, *obj.(*v1.Host))
	}
	return out, nil
}

// apiServers are the API URLs the system nodes report.
func apiServers(hosts []v1.Host) []string {
	var out []string
	for _, h := range hosts {
		if h.Status.ControlPlane != nil && h.Status.ControlPlane.APIURL != "" {
			out = append(out, h.Status.ControlPlane.APIURL)
		}
	}
	return out
}

// hostAddSystemNode sets a fresh machine up as a system node: declared, a one-time token, the
// signed kevasod, and `kevasod control-plane --join …`, which joins the store as a learner, is
// promoted once caught up, and then serves the API (or, state-only, just votes).
func hostAddSystemNode(ctx context.Context, o HostAddOptions, stdin io.Reader, out io.Writer) error {
	say := func(f string, a ...any) { _, _ = fmt.Fprintf(out, "→ "+f+"\n", a...) }
	c, kc, err := adminClient(o.KvoContext)
	if err != nil {
		return err
	}
	hosts, err := listHosts(ctx, c)
	if err != nil {
		return err
	}
	if err := JoinReady(hosts); err != nil {
		return err
	}
	if err := lookFirst(ctx, o.InitOptions, stdin, out); err != nil {
		return err
	}
	o.looked = true
	ca, err := os.ReadFile(kc.CA)
	if err != nil {
		return err
	}
	home := o.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		home = filepath.Join(h, ".kevaso")
	}
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: o.Name},
		Spec: v1.HostSpec{InternalIP: o.InternalIP, ExternalIP: o.ExternalIP, Region: o.Region, Zone: o.Zone,
			Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{StateOnly: o.StateOnly}}}}
	if err := c.Create(ctx, h); err != nil && !client.IsAlreadyExists(err) {
		return fmt.Errorf("register host %s: %w", o.Name, err)
	}
	kind := "system node"
	if o.StateOnly {
		kind = "light system node (state only)"
	}
	say("host %s registered (%s)", o.Name, kind)
	var tok client.JoinTokenResponse
	if err := c.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: o.Name, Roles: []string{roleSystemNode}}, &tok); err != nil {
		return err
	}
	conn, err := bootstrap(ctx, o.InitOptions, home, stdin, out, say)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := installSystemNode(ctx, conn, o, ca, tok.Token, apiServers(hosts), false); err != nil {
		return err
	}
	say("kevasod started: joining the store as a learner (it's promoted once it has caught up)")
	if err := annotateSSH(ctx, c, o.Name, fmt.Sprintf("%s@%s", o.User, net.JoinHostPort(o.Address, strconv.Itoa(o.SSHPort))), conn.Fingerprint); err != nil {
		say("couldn't record how to reach %s (%v)", o.Name, err)
	}
	return finishSystemNode(ctx, c, conn, o, kc, say)
}

// installSystemNode puts the CA, the token and the unit on the machine and starts it.
func installSystemNode(ctx context.Context, conn *sshboot.Conn, o HostAddOptions, ca []byte, token string, servers []string, worker bool) error {
	if len(servers) == 0 {
		return errors.New("no system node reports an API URL to join through")
	}
	if _, err := conn.Run(ctx, "install -d -m 0755 /etc/kevaso", nil); err != nil {
		return err
	}
	if err := conn.Upload(ctx, "/etc/kevaso/ca.crt", ca, 0o644); err != nil {
		return err
	}
	if err := conn.Upload(ctx, "/etc/kevaso/join-token", []byte(token), 0o600); err != nil {
		return err
	}
	return installUnits(ctx, conn, UnitsFor(SystemNodeUnit(o, servers, o.StateOnly, worker), worker && !o.StateOnly, o.InitOptions.Runtimes))
}

// finishSystemNode waits for the new node to vote, and adds its API to the kvo context.
func finishSystemNode(ctx context.Context, c *client.Client, conn *sshboot.Conn, o HostAddOptions, kc kvoconfig.Context, say func(string, ...any)) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		var h v1.Host
		err := c.Get(ctx, "Host", "", o.Name, &h)
		if err == nil && meta.IsTrue(h.Status.Conditions, "Ready") && h.Status.ControlPlane != nil && h.Status.ControlPlane.Member == "voter" {
			if o.StateOnly {
				say("host %s votes in the store (light node: no API, no controllers)", o.Name)
				return nil
			}
			say("host %s votes in the store and serves the API at %s", o.Name, h.Status.ControlPlane.APIURL)
			addServer(kc, o.KvoContext, h.Status.ControlPlane.APIURL, say)
			return nil
		}
		select {
		case <-ctx.Done():
			journal, _ := conn.Run(context.Background(), "journalctl -u kevasod -n 20 --no-pager", nil)
			return fmt.Errorf("host %s didn't become a voting member in 5 minutes\nkevasod on the host:\n%s", o.Name, journal)
		case <-time.After(2 * time.Second):
		}
	}
}

// addServer adds url to the kvo context's server list, so kvo fails over to it.
func addServer(_ kvoconfig.Context, name, url string, say func(string, ...any)) {
	path, err := kvoconfig.Path()
	if err != nil {
		return
	}
	cfg, err := kvoconfig.Load(path)
	if err != nil {
		return
	}
	n, ctx, err := cfg.Resolve(name)
	if err != nil {
		return
	}
	servers := client.SplitServers(ctx.Server)
	for _, s := range servers {
		if s == url {
			return
		}
	}
	ctx.Server = strings.Join(append(servers, url), ",")
	cfg.Contexts[n] = ctx
	if cfg.Save(path) == nil {
		say("kvo context %q now lists %s too (kvo fails over between them)", n, url)
	}
}

// hostInstallControlPlane makes an existing host (a worker) a system node too: SSH with the key
// kvoadm used before, the unit rewritten to join the store, its worker part kept.
func hostInstallControlPlane(ctx context.Context, name string, o HostAddOptions, stdin io.Reader, out io.Writer) error {
	say := func(f string, a ...any) { _, _ = fmt.Fprintf(out, "→ "+f+"\n", a...) }
	c, kc, err := adminClient(o.KvoContext)
	if err != nil {
		return err
	}
	hosts, err := listHosts(ctx, c)
	if err != nil {
		return err
	}
	if err := JoinReady(hosts); err != nil {
		return err
	}
	var h *v1.Host
	for i := range hosts {
		if hosts[i].Name == name {
			h = &hosts[i]
		}
	}
	if h == nil {
		return fmt.Errorf("no host %s", name)
	}
	if h.Spec.Components.ControlPlane != nil {
		return fmt.Errorf("%s already has the control-plane component", name)
	}
	user, addr, port, ok := sshTarget(h)
	if !ok {
		return fmt.Errorf("kvoadm doesn't know how to reach %s over SSH (no %s annotation)", name, AnnotationSSH)
	}
	io2 := o.InitOptions
	io2.User, io2.Address, io2.SSHPort, io2.HostKey, io2.Name = user, addr, port, h.Annotations[AnnotationSSHHostKey], name
	defaultSSHKey(&io2)
	ca, err := os.ReadFile(kc.CA)
	if err != nil {
		return err
	}
	conn, _, err := dialHost(ctx, io2, bufio.NewReader(stdin), stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	for attempt := 0; ; attempt++ {
		var cur v1.Host
		if err := c.Get(ctx, "Host", "", name, &cur); err != nil {
			return err
		}
		cur.Spec.Components.ControlPlane = &v1.ControlPlaneSpec{StateOnly: o.StateOnly}
		err := c.Update(ctx, &cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) || attempt > 5 {
			return err
		}
	}
	var tok client.JoinTokenResponse
	if err := c.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: name, Roles: []string{roleSystemNode}}, &tok); err != nil {
		return err
	}
	o.InitOptions = io2
	o.InternalIP, o.ExternalIP = h.Spec.InternalIP, h.Spec.ExternalIP
	o.Runtimes = append(o.Runtimes, runtimesOf(h)...)
	o.InitOptions.Runtimes = o.Runtimes
	worker := h.Spec.Components.Worker != nil && !o.StateOnly
	if err := installSystemNode(ctx, conn, o, ca, tok.Token, apiServers(hosts), worker); err != nil {
		return err
	}
	say("%s restarted as a system node: joining the store as a learner", name)
	return finishSystemNode(ctx, c, conn, o, kc, say)
}

func runtimesOf(h *v1.Host) []string {
	if h.Spec.Components.Worker == nil {
		return nil
	}
	var out []string
	for _, r := range h.Spec.Components.Worker.Runtimes {
		out = append(out, r.Name)
	}
	return out
}

// hostRemoveSystemNode takes the control-plane component off a host: its store membership goes
// first (the leader's member controller removes it, keeping the majority), refused when it
// would lose the majority. remove also deletes the Host when nothing else is installed.
func hostRemoveSystemNode(ctx context.Context, name, kctx string, deleteHost bool, out io.Writer) error {
	c, _, err := adminClient(kctx)
	if err != nil {
		return err
	}
	return RemoveSystemNode(ctx, c, name, deleteHost, out)
}

// RemoveSystemNode is host uninstall … control-plane (deleteHost false) and host remove (true)
// through an admin client. A system node that is a worker too keeps its Host, without the
// control-plane component; one that is only a system node can't be left with no component, so
// uninstall is refused and remove deletes the Host held by etcd.FinalizerMember: a Host being
// deleted asks for no member, the member controller removes the member, then lets the Host go.
func RemoveSystemNode(ctx context.Context, c *client.Client, name string, deleteHost bool, out io.Writer) error {
	say := func(f string, a ...any) { _, _ = fmt.Fprintf(out, "→ "+f+"\n", a...) }
	hosts, err := listHosts(ctx, c)
	if err != nil {
		return err
	}
	var h *v1.Host
	for i := range hosts {
		if hosts[i].Name == name {
			h = &hosts[i]
		}
	}
	if h == nil {
		return fmt.Errorf("no host %s", name)
	}
	if h.Spec.Components.ControlPlane == nil {
		if !deleteHost {
			return fmt.Errorf("%s has no control-plane component", name)
		}
		return removeWorkerHost(ctx, c, name, say)
	}
	onlySystem := h.Spec.Components.Worker == nil
	if onlySystem && !deleteHost {
		return fmt.Errorf("%s runs only the control-plane component: a host needs one, so remove the host instead (kvoadm host remove %s)", name, name)
	}
	if err := RemovalCheck(hosts, name, time.Now(), 40*time.Second); err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		var cur v1.Host
		if err := c.Get(ctx, "Host", "", name, &cur); err != nil {
			return err
		}
		if onlySystem {
			if !slices.Contains(cur.Finalizers, etcd.FinalizerMember) {
				cur.Finalizers = append(cur.Finalizers, etcd.FinalizerMember)
			}
		} else {
			cur.Spec.Components.ControlPlane = nil
		}
		err := c.Update(ctx, &cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) || attempt > 5 {
			return err
		}
	}
	if onlySystem {
		if err := c.Delete(ctx, "Host", "", name); err != nil && !client.IsNotFound(err) {
			return err
		}
	}
	say("%s no longer asks for a store member; waiting for the member to be removed", name)
	wctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		var cur v1.Host
		err := c.Get(wctx, "Host", "", name, &cur)
		if client.IsNotFound(err) { // held until its member was removed
			say("%s left the store", name)
			say("host %s removed from the cluster; the machine itself is yours (stop it: systemctl disable --now kevasod)", name)
			return nil
		}
		if err != nil {
			return err
		}
		if !onlySystem && (cur.Status.ControlPlane == nil || cur.Status.ControlPlane.Member == "") {
			say("%s left the store; its kevasod stops serving the control plane (its worker part stays)", name)
			return nil
		}
		select {
		case <-wctx.Done():
			return fmt.Errorf("%s is still a store member after 2 minutes: see the leader's log", name)
		case <-time.After(time.Second):
		}
	}
}

func removeWorkerHost(ctx context.Context, c *client.Client, name string, say func(string, ...any)) error {
	l, err := c.List(ctx, "Silo", "")
	if err != nil {
		return err
	}
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return err
		}
		if s := obj.(*v1.Silo); s.Status.Host == name {
			return fmt.Errorf("silo %s/%s is on %s: kvoadm host drain %s first", s.Namespace, s.Name, name, name)
		}
	}
	if err := c.Delete(ctx, "Host", "", name); err != nil {
		return err
	}
	say("host %s removed from the cluster; the machine itself is yours (stop it: systemctl disable --now kevasod)", name)
	return nil
}

// storeMigrate switches the control plane at [USER@]ADDRESS to etcd with a peer listener: once,
// before a second system node joins. Its kevasod restarts (the API is away a moment, watches
// re-list); store.db moves into etcd on that start.
func storeMigrate(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	say := func(f string, a ...any) { _, _ = fmt.Fprintf(out, "→ "+f+"\n", a...) }
	var kctx string
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--context" && i+1 < len(args) {
			kctx = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	o, err := parseTarget(rest)
	if err != nil {
		return err
	}
	defaultSSHKey(&o)
	if err := needCredential(o); err != nil {
		return err
	}
	c, _, err := adminClient(kctx)
	if err != nil {
		return err
	}
	conn, _, err := dialHost(ctx, o, bufio.NewReader(stdin), stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	unit, err := conn.Run(ctx, "cat /etc/systemd/system/kevasod.service", nil)
	if err != nil {
		return err
	}
	name := unitFlag(string(unit), "--name")
	addr := unitFlag(string(unit), "--external-ip")
	if addr == "" {
		addr = unitFlag(string(unit), "--internal-ip")
	}
	if addr == "" {
		addr = o.Address
	}
	updated, changed, err := WithEtcd(string(unit), net.JoinHostPort(addr, etcd.DefaultPeerPort))
	if err != nil {
		return err
	}
	if !changed {
		say("%s already keeps its state in etcd with a peer listener", name)
		return nil
	}
	if err := conn.InstallUnit(ctx, "kevasod.service", []byte(updated)); err != nil {
		return err
	}
	say("%s restarted with --store etcd (store.db moves into etcd on this start; watchers re-list)", name)
	wctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for {
		var h v1.Host
		if err := c.Get(wctx, "Host", "", name, &h); err == nil && h.Status.ControlPlane != nil && h.Status.ControlPlane.Store == "etcd" && h.Status.ControlPlane.PeerURL != "" {
			say("%s keeps its state in etcd, peers at %s: kvoadm host add … --install control-plane can join more", name, h.Status.ControlPlane.PeerURL)
			return nil
		}
		select {
		case <-wctx.Done():
			journal, _ := conn.Run(context.Background(), "journalctl -u kevasod -n 20 --no-pager", nil)
			return fmt.Errorf("%s didn't report an etcd store in 3 minutes\nkevasod on the host:\n%s", name, journal)
		case <-time.After(2 * time.Second):
		}
	}
}
