package cloudhypervisor

import (
	"context"
	"fmt"
	"strings"
)

// A command that changes the thin pool (lvcreate, lvremove, lvchange) rewrites the pool's
// metadata. kevasod runs it as a child, and systemd's default KillMode=control-group kills
// every process in kevasod's cgroup when the unit stops or its main process exits: an upgrade,
// a crash, a restart. Killed mid-update, LVM can leave the pool's metadata volume (silos_tmeta)
// or its data volume (silos_tdata) active while the pool itself is not. From then on every
// lvcreate and lvremove fails with "Activation of logical volume kevaso/silos is prohibited
// while logical volume kevaso/silos_tmeta is active", and no new microVM can be made until the
// pool is repaired by hand.
//
// runPool keeps that from happening, and repairs a pool it already happened to.
//
// The command runs in its own transient scope in system.slice, outside kevasod's cgroup, so
// the restart's cgroup kill does not reach it. A scope, rather than KillMode=process on
// kevasod: that would spare every child, and a restart is supposed to kill qemu-img convert so
// a half-made disk is made again and never booted. KillMode would also not cover systemctl
// kill, which signals the whole cgroup whatever KillMode says, and it lives in the unit file,
// which an already-installed host does not pick up until that file is rewritten. A scope is one
// command, it inherits this process's environment (LVM's errors stay what run reports), and
// only the pool command leaves the cgroup. A transient service starts with a clean environment,
// so the errors would not be the ones a direct lvcreate reports. Moving the process into a
// cgroup by hand is the same request of the manager without a unit to own the process.
//
// Before the command, a pool whose metadata or data volume is active while the pool is not has
// those volumes deactivated and is activated again. That is the whole repair. The pool and
// every silo's volume stay; a repair that fails names that state and the lvchange to run by
// hand.

// runPool runs an LVM command that changes the thin pool: repaired first if a killed command
// left it unusable, and outside kevasod's cgroup so this command is not killed the same way.
func (r *Runtime) runPool(ctx context.Context, name string, args ...string) error {
	if err := r.repairThinPool(ctx); err != nil {
		return err
	}
	return r.runDetached(ctx, name, args...)
}

// runDetached runs name outside kevasod's cgroup. A failure is reported as run reports it:
// the command's own name, arguments, and output, not systemd-run's.
func (r *Runtime) runDetached(ctx context.Context, name string, args ...string) error {
	sargs := make([]string, 0, 6+len(args))
	sargs = append(sargs, "--quiet", "--collect", "--scope", "--slice=system.slice", "--", name)
	sargs = append(sargs, args...)
	out, err := r.Host.Run(ctx, "systemd-run", sargs...)
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// repairThinPool deactivates silos_tmeta and silos_tdata when one of them is active and the
// pool is not, then activates the pool. A pool that is already active is left alone: its
// sub-volumes are active with it, and deactivating them would take the disks out from under
// running microVMs. No pool yet, or an lvs that fails, is not this state; the command that
// follows reports its own error.
func (r *Runtime) repairThinPool(ctx context.Context) error {
	out, err := r.Host.Run(ctx, "lvs", "-a", "--noheadings", "-o", "lv_name,lv_active", VG)
	if err != nil {
		return nil
	}
	active := stuckSubLVs(string(out))
	if len(active) == 0 {
		return nil
	}
	args := make([]string, 1, 1+len(active))
	args[0] = "-an"
	paths := make([]string, len(active))
	for i, n := range active {
		paths[i] = VG + "/" + n
		args = append(args, paths[i])
	}
	if err := r.runDetached(ctx, "lvchange", args...); err != nil {
		return stuckPoolError(paths, err)
	}
	if err := r.runDetached(ctx, "lvchange", "-ay", VG+"/"+ThinPool); err != nil {
		return stuckPoolError(paths, err)
	}
	return nil
}

// stuckSubLVs is the pool's metadata and data volumes that are active while the pool itself
// is not, metadata first. Empty when the pool is missing, active, or its sub-volumes are not.
func stuckSubLVs(out string) []string {
	var poolSeen, poolUp bool
	up := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		name := strings.Trim(f[0], "[]")
		on := len(f) > 1 && strings.HasPrefix(f[1], "active")
		switch name {
		case ThinPool:
			poolSeen, poolUp = true, on
		case ThinPool + "_tmeta", ThinPool + "_tdata":
			up[name] = on
		}
	}
	if !poolSeen || poolUp {
		return nil
	}
	var active []string
	for _, n := range []string{ThinPool + "_tmeta", ThinPool + "_tdata"} {
		if up[n] {
			active = append(active, n)
		}
	}
	return active
}

func stuckPoolError(vols []string, err error) error {
	list := strings.Join(vols, " and ")
	verb := "is"
	if len(vols) > 1 {
		verb = "are"
	}
	return fmt.Errorf("thin pool %s/%s is unusable: %s %s active while %s/%s is not (a pool command was killed mid-way): %w. Nothing was removed. Repair it by hand: lvchange -an %s && lvchange -ay %s/%s",
		VG, ThinPool, list, verb, VG, ThinPool, err, strings.Join(vols, " "), VG, ThinPool)
}
