//go:build darwin

package mesh

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// On a Mac there is no kernel WireGuard: the interface is a utun device driven by wireguard-go
// inside kevasod (it needs root, as kevasod runs there). The device answers wgctrl on a socket
// named for the interface (/var/run/wireguard/kevaso0.sock), so the same Diff that keeps a
// Linux host's interface current keeps this one's: only the interface and its routes differ.
// A Mac never relays (no IP forwarding for others), so Desired.Forward is refused.

type udev struct {
	utun   string // the real interface name the system gave (utun7)
	dev    *device.Device
	routes []string
}

var (
	macMu   sync.Mutex
	macDevs = map[string]*udev{}
)

// runCmd runs a system command; tests replace it.
var runCmd = func(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Apply makes the host's interfaces match d with wireguard-go and route(8).
func Apply(d Desired, outerKey, innerKey wgtypes.Key) error {
	if d.Forward {
		return fmt.Errorf("a Mac doesn't relay the mesh (no IP forwarding): pick a Linux host as the relay")
	}
	macMu.Lock()
	defer macMu.Unlock()
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() { _ = wg.Close() }()
	if err := applyMac(wg, d.Outer, outerKey); err != nil {
		return err
	}
	if d.Inner != nil {
		return applyMac(wg, *d.Inner, innerKey)
	}
	if u, ok := macDevs[Inner]; ok { // no longer behind NAT: drop the inner interface
		u.dev.Close()
		delete(macDevs, Inner)
	}
	return nil
}

func ensureMac(want Iface) (*udev, error) {
	if u, ok := macDevs[want.Name]; ok {
		return u, nil
	}
	t, err := tun.CreateTUN("utun", want.MTU)
	if err != nil {
		return nil, fmt.Errorf("create a utun for %s (kevasod must run as root): %w", want.Name, err)
	}
	utun, err := t.Name()
	if err != nil {
		_ = t.Close()
		return nil, err
	}
	dev := device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "("+want.Name+") "))
	f, err := ipc.UAPIOpen(want.Name)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("%s control socket: %w", want.Name, err)
	}
	l, err := ipc.UAPIListen(want.Name, f)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("%s control socket: %w", want.Name, err)
	}
	go serveUAPI(l, dev)
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	u := &udev{utun: utun, dev: dev}
	macDevs[want.Name] = u
	return u, nil
}

func serveUAPI(l net.Listener, dev *device.Device) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go dev.IpcHandle(c)
	}
}

func applyMac(wg *wgctrl.Client, want Iface, priv wgtypes.Key) error {
	u, err := ensureMac(want)
	if err != nil {
		return err
	}
	cur, err := wg.Device(want.Name)
	if err != nil {
		cur = nil
	}
	cfg, changed, err := Diff(want, priv, cur)
	if err != nil {
		return err
	}
	if changed {
		if err := wg.ConfigureDevice(want.Name, cfg); err != nil {
			return fmt.Errorf("configure %s: %w", want.Name, err)
		}
	}
	host, err := hostOf(want.Address)
	if err != nil {
		return err
	}
	for _, a := range ifconfigArgs(u.utun, host, want.MTU) {
		if err := runCmd(a...); err != nil {
			return fmt.Errorf("%s address: %w", want.Name, err)
		}
	}
	net, err := networkOf(want.Address)
	if err != nil {
		return err
	}
	add, del := routePlan(u.routes, append([]string{net}, want.Routes...))
	for _, r := range del {
		_ = runCmd(routeArgs("delete", r, u.utun)...)
	}
	for _, r := range add {
		_ = runCmd(routeArgs("delete", r, u.utun)...) // one left from an earlier run of kevasod
		if err := runCmd(routeArgs("add", r, u.utun)...); err != nil {
			return fmt.Errorf("route %s via %s: %w", r, want.Name, err)
		}
	}
	u.routes = append([]string{net}, want.Routes...)
	return nil
}
