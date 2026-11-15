package openshell

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fake is a host with systemd, Docker and an OpenShell CLI, all in memory.
//
// It models what the machines showed of OpenShell v0.1.8 (metal.md, 2026-11-15), which the fake
// before it could not express: it had no unit state (a gateway "answered" from the moment
// `systemctl enable` ran and for ever after), so a gateway could not stop, crash, hang, restart by
// itself or come up at boot; a stopped gateway's sandboxes kept their phase as if they still ran;
// there was no difference between what the gateway says and what runs (no VM process, no
// container); a missing registration and a missing sandbox were the same "not found"; and nothing
// could reboot.
//
//   - A gateway answers only while its unit is active, registered with the CLI, and not hung.
//   - Stopping the unit (or a crash) takes the VM driver's sandboxes with it (KillMode=control-
//     group); the Docker driver's containers live under dockerd and keep running.
//   - Starting the unit restores every sandbox its record says was Ready (seen on both drivers);
//     the VM driver's then reads Error ("already running", seen on machine 2). A Stopped one stays
//     stopped unless restoresStopped is set: that is the experiment still to run (item 5).
//   - systemd restarts a crashed unit only when its file says Restart=on-failure or always, and
//     starts an enabled unit at boot.
type fake struct {
	files      map[string][]byte
	cmds       []string // argv of every command, joined
	envs       []string // env of every command, joined
	sandboxes  map[string]*fsb
	users      map[string]bool
	units      map[string]string // unit → active | inactive | failed
	enabled    map[string]bool
	hung       map[string]bool // gateway name → its unit is active but it doesn't answer
	registered map[string]bool
	containers map[string]bool // Docker container name → running
	execCode   int
	execHook   func(context.Context, Cmd) (int, error) // sandbox exec, if set

	restoresStopped bool            // a gateway that starts brings its Stopped sandboxes back too
	dockerAtBoot    bool            // the Docker driver's containers start with dockerd at boot
	listFails       bool            // sandbox list doesn't answer either
	stopLies        bool            // sandbox stop says Stopped, and the Docker driver's container runs on
	failOn          string          // an openshell command containing this fails
	providers       map[string]bool // provider name → in the gateway's credential store
	// comesUp: a unit found activating (started by someone, not yet listening) that becomes active
	// at the next `gateway add` of its gateway, restoring its sandboxes as a start does.
	comesUp map[string]bool
}

// fsb is one sandbox as the gateway records it.
type fsb struct {
	gw    string // gateway name
	phase string
}

const bootIDFile = "/proc/sys/kernel/random/boot_id"

func newFake() *fake {
	return &fake{files: map[string][]byte{bootIDFile: []byte("boot-1\n")}, sandboxes: map[string]*fsb{}, users: map[string]bool{},
		units: map[string]string{}, enabled: map[string]bool{}, hung: map[string]bool{}, registered: map[string]bool{},
		containers: map[string]bool{}, providers: map[string]bool{}}
}

func gatewayOf(env []string) string {
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "OPENSHELL_GATEWAY="); ok {
			return v
		}
	}
	return ""
}

func unitOfGateway(name string) string {
	return unitStart + strings.TrimPrefix(name, "kv-") + ".service"
}
func gatewayOfUnit(unit string) string {
	return "kv-" + strings.TrimSuffix(strings.TrimPrefix(unit, unitStart), ".service")
}

func (f *fake) driver(gw string) string {
	if strings.HasPrefix(gw, "kv-"+DriverDocker+"-") {
		return DriverDocker
	}
	return DriverVM
}

// answers: the gateway is up, registered and not hung.
func (f *fake) answers(gw string) bool {
	return f.units[unitOfGateway(gw)] == "active" && !f.hung[gw] && f.registered[gw]
}

// Runs reports whether anything of sandbox name runs on the host, by looking (not by the
// gateway's word): the VM under its active unit, or its container.
func (f *fake) Runs(name string) bool {
	sb, ok := f.sandboxes[name]
	if !ok {
		return false
	}
	if f.driver(sb.gw) == DriverDocker {
		return f.containers[name]
	}
	return f.units[unitOfGateway(sb.gw)] == "active" && (sb.phase == "Ready" || sb.phase == "Error")
}

func (f *fake) startUnit(unit string) {
	if f.units[unit] == "active" {
		return
	}
	f.units[unit] = "active"
	gw := gatewayOfUnit(unit)
	for name, sb := range f.sandboxes {
		if sb.gw != gw {
			continue
		}
		if sb.phase == "Ready" || (f.restoresStopped && sb.phase == "Stopped") {
			sb.phase = "Ready"
			if f.driver(gw) == DriverDocker {
				f.containers[name] = true
			} else {
				sb.phase = "Error" // the VM comes back, the gateway then refuses it (machine 2)
			}
		}
	}
}

func (f *fake) stopUnit(unit, to string) {
	f.units[unit] = to // VM sandboxes stop with the cgroup; their record stays as it was
}

// Crash: the gateway dies. systemd restarts it only if its unit file says so.
func (f *fake) Crash(gw string) {
	unit := unitOfGateway(gw)
	f.stopUnit(unit, "failed")
	if u := string(f.files["/etc/systemd/system/"+unit]); strings.Contains(u, "Restart=on-failure") || strings.Contains(u, "Restart=always") {
		f.startUnit(unit)
	}
}

// Reboot: every unit stops, every container stops; enabled units start again, and so do
// containers if Docker restarts them.
func (f *fake) Reboot() {
	f.files[bootIDFile] = []byte(string(f.files[bootIDFile][:len(f.files[bootIDFile])-1]) + "+\n")
	for u := range f.units {
		f.units[u] = "inactive"
	}
	if !f.dockerAtBoot {
		for c := range f.containers {
			f.containers[c] = false
		}
	}
	units := make([]string, 0, len(f.enabled))
	for u, on := range f.enabled {
		if on {
			units = append(units, u)
		}
	}
	sort.Strings(units)
	for _, u := range units {
		f.startUnit(u)
	}
}

func (f *fake) Run(ctx context.Context, c Cmd) (int, error) {
	line := c.Name + " " + strings.Join(c.Args, " ")
	f.cmds = append(f.cmds, line)
	f.envs = append(f.envs, strings.Join(c.Env, " "))
	out := func(s string) {
		if c.Stdout != nil {
			_, _ = io.WriteString(c.Stdout, s)
		}
	}
	fail := func(s string) (int, error) {
		if c.Stderr != nil {
			_, _ = io.WriteString(c.Stderr, s)
		}
		return 1, nil
	}
	a := c.Args
	switch {
	case c.Name == "id":
		if !f.users[a[1]] {
			return 1, nil
		}
	case c.Name == "useradd":
		f.users[a[len(a)-1]] = true
	case c.Name == "userdel":
		delete(f.users, a[len(a)-1])
	case c.Name == "systemctl" && len(a) >= 2:
		unit := a[len(a)-1]
		switch a[0] {
		case "enable":
			f.enabled[unit] = true
			if a[1] == "--now" {
				f.startUnit(unit)
			}
		case "disable":
			f.enabled[unit] = false
			if a[1] == "--now" {
				f.stopUnit(unit, "inactive")
			}
		case "start":
			f.startUnit(unit)
		case "stop":
			f.stopUnit(unit, "inactive")
		case "is-active":
			st := f.units[unit]
			if st == "" {
				st = "inactive"
			}
			out(st + "\n")
			if st != "active" {
				return 3, nil
			}
		}
	case c.Name == "docker" && len(a) > 0 && a[0] == "ps":
		all := len(a) > 1 && a[1] == "-a"
		var names []string
		for n, on := range f.containers {
			if on || all {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			out("openshell-" + n + "\n")
		}
	case c.Name == "docker" && len(a) > 2 && a[0] == "rm" && a[1] == "-f":
		for _, n := range a[2:] {
			delete(f.containers, strings.TrimPrefix(n, "openshell-"))
		}
	case c.Name == "docker" && len(a) > 1 && a[0] == "stop":
		for _, n := range a[1:] {
			f.containers[strings.TrimPrefix(n, "openshell-")] = false
		}
	case c.Name == "openshell":
		gw := gatewayOf(c.Env)
		if len(a) >= 2 && a[0] == "gateway" && a[1] == "add" {
			if u := unitOfGateway(gw); f.comesUp[u] && f.units[u] == "activating" {
				delete(f.comesUp, u)
				f.units[u] = "inactive"
				f.startUnit(u)
			}
			if f.units[unitOfGateway(gw)] != "active" || f.hung[gw] {
				return fail("connect error: transport error")
			}
			if f.registered[gw] {
				return fail("gateway already exists")
			}
			f.registered[gw] = true
			return 0, nil
		}
		if !f.registered[gw] {
			return fail("gateway '" + gw + "' not found") // OpenShell's words for an unknown gateway name
		}
		if !f.answers(gw) {
			return fail("connect error: transport error")
		}
		if f.failOn != "" && strings.Contains(line, f.failOn) {
			return fail("internal error")
		}
		switch {
		case a[0] == "provider" && a[1] == "create":
			if f.providers[a[3]] {
				return fail("provider already exists")
			}
			f.providers[a[3]] = true
		case a[0] == "provider" && a[1] == "delete":
			if !f.providers[a[2]] {
				return fail("provider not found")
			}
			delete(f.providers, a[2])
		case a[0] == "sandbox" && a[1] == "list":
			if f.listFails {
				return fail("connect error: transport error")
			}
			var list []sandboxJSON
			for n, sb := range f.sandboxes {
				if sb.gw == gw {
					list = append(list, sandboxJSON{Name: n, Phase: sb.phase})
				}
			}
			b, _ := json.Marshal(list)
			out(string(b))
		case a[0] == "sandbox" && a[1] == "create":
			f.sandboxes[a[3]] = &fsb{gw: gw, phase: "Ready"}
			if f.driver(gw) == DriverDocker {
				f.containers[a[3]] = true
			}
			out(`{"phase":"Ready"}`)
		case a[0] == "sandbox" && a[1] == "get":
			sb, ok := f.sandboxes[a[2]]
			if !ok || sb.gw != gw {
				return fail("sandbox not found")
			}
			b, _ := json.Marshal(sandboxJSON{Name: a[2], Phase: sb.phase})
			out(string(b))
		case a[0] == "sandbox" && a[1] == "stop":
			if sb, ok := f.sandboxes[a[2]]; ok {
				sb.phase = "Stopped"
				if !f.stopLies && f.driver(gw) == DriverDocker {
					f.containers[a[2]] = false
				}
			}
		case a[0] == "sandbox" && a[1] == "start":
			sb, ok := f.sandboxes[a[2]]
			if !ok {
				return fail("sandbox not found")
			}
			if sb.phase == "Error" { // what the real one says (seen on machine 2)
				return fail("code: 'The system is not in a state required for the operation's execution'")
			}
			sb.phase = "Ready"
			if f.driver(gw) == DriverDocker {
				f.containers[a[2]] = true
			}
		case a[0] == "sandbox" && a[1] == "delete":
			delete(f.sandboxes, a[2])
			delete(f.containers, a[2])
		case a[0] == "sandbox" && a[1] == "exec" && f.execHook != nil:
			return f.execHook(ctx, c)
		case a[0] == "sandbox" && a[1] == "exec":
			if c.Stdin != nil {
				b, _ := io.ReadAll(c.Stdin)
				out(string(b))
			}
			return f.execCode, nil
		}
	}
	return 0, nil
}

func (f *fake) WriteFile(p string, d []byte, _ os.FileMode) error {
	f.files[p] = append([]byte(nil), d...)
	return nil
}
func (f *fake) ReadFile(p string) ([]byte, error) {
	if b, ok := f.files[p]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}
func (f *fake) RemoveAll(p string) error {
	for k := range f.files {
		if k == p || strings.HasPrefix(k, p+"/") {
			delete(f.files, k)
		}
	}
	return nil
}
func (f *fake) Glob(pattern string) ([]string, error) {
	var out []string
	for k := range f.files {
		if ok, _ := filepath.Match(pattern, k); ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Glob0 is Glob without its error.
func (f *fake) Glob0(pattern string) []string { m, _ := f.Glob(pattern); return m }

func (f *fake) ran(sub string) int {
	n := 0
	for _, c := range f.cmds {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}
