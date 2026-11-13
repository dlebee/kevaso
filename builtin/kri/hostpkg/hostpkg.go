// Package hostpkg is the one door the built-in runtimes use to the host's package manager.
//
// Several runtimes install on the same host at the same time (a host with both
// cloud-hypervisor and docker), and apt takes exclusive locks: two installs at once fail with
// "Could not get lock". So every runtime takes Lock before it runs apt, and passes Opts so apt
// waits for anything else on the machine that holds dpkg's lock (unattended upgrades).
package hostpkg

import "sync"

var mu sync.Mutex

// Lock serializes package installs inside this process. Call the returned function when done.
func Lock() (unlock func()) {
	mu.Lock()
	return mu.Unlock
}

// LockTimeout is how long apt waits for another program's dpkg lock.
const LockTimeout = "DPkg::Lock::Timeout=300"

// Update is a shell line that refreshes the package lists, waiting for another program that is
// refreshing them (apt has no timeout for that lock).
const Update = `n=0; until apt-get update -q; do n=$((n+1)); [ "$n" -ge 30 ] && exit 100; sleep 10; done`
