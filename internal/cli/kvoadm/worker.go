package kvoadm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// workerFlags are the control-plane unit's worker settings (replaced as a whole by enable-worker).
var workerFlags = map[string]bool{"--worker": false, "--runtime": true, "--loop-storage": true, "--loop-size": true, "--storage-device": true,
	"--egress-extra-ca": true, "--openshell-gateway-scope": true} // flag → takes a value

// WithWorker rewrites a control-plane unit so that host also runs silos: the worker flags in its
// ExecStart are replaced by o's. Pure.
func WithWorker(unit string, o InitOptions) (string, error) {
	lines := strings.Split(unit, "\n")
	for i, l := range lines {
		rest, ok := strings.CutPrefix(l, "ExecStart=/usr/local/bin/kevasod ")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 || f[0] != "control-plane" {
			return "", errors.New("this host's kevasod isn't a control plane (worker-only hosts are added with kvoadm host add)")
		}
		var keep []string
		for j := 0; j < len(f); j++ {
			if takesValue, isWorker := workerFlags[f[j]]; isWorker {
				if takesValue {
					j++
				}
				continue
			}
			keep = append(keep, f[j])
		}
		o.Worker = true
		keep = append(keep, workerArgs(o)...)
		lines[i] = "ExecStart=/usr/local/bin/kevasod " + strings.Join(keep, " ")
		return strings.Join(lines, "\n"), nil
	}
	return "", errors.New("no kevasod ExecStart in the unit: is the control plane installed here (kvoadm init)?")
}

// workerArgs are kevasod's worker flags for o.
func workerArgs(o InitOptions) []string {
	args := []string{"--worker"}
	rts := o.Runtimes
	if len(rts) == 0 {
		rts = []string{"cloud-hypervisor"}
	}
	for _, r := range rts {
		args = append(args, "--runtime", r)
	}
	if o.LoopStorage != "" {
		args = append(args, "--loop-storage", "/var/lib/kevaso-storage.img", "--loop-size", o.LoopStorage)
	}
	if o.StorageDevice != "" {
		args = append(args, "--storage-device", o.StorageDevice)
	}
	if o.EgressExtraCA != "" {
		args = append(args, "--egress-extra-ca", o.EgressExtraCA)
	}
	if o.GatewayScope != "" {
		args = append(args, "--openshell-gateway-scope", o.GatewayScope)
	}
	return args
}

// enableWorker: kvoadm host enable-worker [USER@]ADDRESS --ssh-key PATH [--host-key …] [--runtime R]…
// [--loop-storage SIZE] — the control-plane host also runs silos (a one-host cluster, or a small one).
func enableWorker(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	o, err := parseTarget(args)
	if err != nil {
		return err
	}
	if err := needCredential(o); err != nil {
		return err
	}
	conn, _, err := dialHost(ctx, o, bufio.NewReader(stdin), stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	unit, err := conn.Run(ctx, "cat /etc/systemd/system/kevasod.service", nil)
	if err != nil {
		return fmt.Errorf("reading kevasod.service: %w (is the control plane installed? kvoadm init)", err)
	}
	next, err := WithWorker(string(unit), o)
	if err != nil {
		return err
	}
	rts := o.Runtimes
	if len(rts) == 0 {
		rts = []string{"cloud-hypervisor"}
	}
	if err := installUnits(ctx, conn, UnitsFor(next, true, rts)); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "→ kevasod restarted with the worker (%s), and its fence (%s). Its runtimes install now: kvo watch hosts\n", strings.Join(rts, ", "), FenceUnitName)
	return nil
}
