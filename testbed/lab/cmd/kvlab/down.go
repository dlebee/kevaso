package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kevaso.com/core/testbed/lab"
)

func cmdDown(args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	name := nameFlag(args, fs)
	if err := lab.ValidName(name); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	h, err := dialHost(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	script, err := lab.DestroyScript(name)
	if err != nil {
		return err
	}
	if _, err := h.run(ctx, script); err != nil {
		return fmt.Errorf("removing lab %s: %w", name, err)
	}
	root, err := moduleRoot()
	if err != nil {
		return err
	}
	local := labDir(root, name)
	if err := os.RemoveAll(local); err != nil {
		return err
	}
	fmt.Printf("lab %s is gone (nothing named kvl-%s remains on the host, and %s is removed)\n", name, name, local)
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	h, err := dialHost(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	out, err := h.run(ctx, listScript)
	if err != nil {
		return err
	}
	facts := parseFacts(out)
	if len(facts["lab"]) == 0 && len(facts["vm"]) == 0 {
		fmt.Println("no labs")
		return nil
	}
	fmt.Printf("%-12s %-4s %-16s %-8s %-8s %-8s %-8s %s\n", "NAME", "SLOT", "NETWORK", "SYS", "W1", "W2", "API", "VMS")
	seen := map[string]bool{}
	for _, line := range facts["lab"] {
		name, slotS, ok := cut2(line)
		if !ok {
			continue
		}
		seen[name] = true
		var slot int
		if _, err := fmt.Sscanf(slotS, "%d", &slot); err != nil {
			fmt.Printf("%-12s %s\n", name, slotS)
			continue
		}
		p, err := lab.PortsFor(slot)
		if err != nil {
			fmt.Printf("%-12s %s\n", name, slotS)
			continue
		}
		fmt.Printf("%-12s %-4d %-16s %-8d %-8d %-8d %-8d %s\n",
			name, slot, lab.CIDR(slot), p.SysSSH, p.W1SSH, p.W2SSH, p.API, vmStates(name, facts["vm"]))
	}
	for _, line := range facts["vm"] {
		vm, _, ok := cut2(line)
		if !ok {
			continue
		}
		// A domain whose lab directory is already gone still shows, so it can be removed.
		known := false
		for name := range seen {
			if strings.HasPrefix(vm, lab.VMName(name, "")) {
				// VMName(name, "") is kvl-NAME-, the prefix of kvl-NAME-sys.
				known = true
			}
		}
		if !known {
			fmt.Printf("(domain without a lab directory) %s\n", line)
		}
	}
	return nil
}

const listScript = `set -eu
[ -d /root/kvl ] || exit 0
for d in /root/kvl/*/; do
  [ -f "${d}slot" ] || continue
  name=$(basename "$d")
  slot=$(tr -d '[:space:]' < "${d}slot")
  echo "lab=$name $slot"
done
virsh list --all --name | while read -r n; do
  case "$n" in
  kvl-*) echo "vm=$n $(virsh domstate "$n")";;
  esac
done
`

func vmStates(name string, vms []string) string {
	var parts []string
	for _, role := range []string{"sys", "w1", "w2"} {
		vm := lab.VMName(name, role)
		st := "absent"
		for _, line := range vms {
			if v, state, ok := cut2(line); ok && v == vm {
				st = state
			}
		}
		parts = append(parts, role+"="+st)
	}
	return joinSpace(parts)
}

func joinSpace(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

func labDir(root, name string) string {
	return filepath.Join(root, "testbed", "lab", ".labs", name)
}
