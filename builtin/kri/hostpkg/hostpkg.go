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

// InstalledFile lists, one per line, every package Kevaso's runtimes installed on this host (with
// the dependencies apt brought along): only those are Kevaso's to purge on a reset (K-113). A
// package that is there now and not in the install record may be the host owner's, installed
// after Kevaso. It sits with the install record (kvoadm's /var/lib/kevaso-install), which the
// reset reads and then removes.
const InstalledFile = "/var/lib/kevaso-install/installed"

// installedNow prints the installed packages, sorted for comm.
const installedNow = `dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1 == "ii" {print $2}' | LC_ALL=C sort -u`

// Recording is the shell script that runs install (an apt-get install line; "$@" is passed
// through) and appends to InstalledFile what it newly installed. The record is made whatever the
// install's outcome (a failed install may have installed some), and the install's exit status is
// the script's.
func Recording(install string) string { return recording(install, InstalledFile) }

// The snapshot of what was there before is kept next to the file, one per package list, until the
// record is written: a kevasod restart that cuts the script off after apt-get has installed but
// before the record is written leaves the snapshot, and the next run of the same install (when
// kevasod starts again) counts from it. Without that, what apt-get had installed was found already
// there and never recorded, and a reset left it (found on a real machine: docker.io, with its
// firewall tables and IP forwarding). A snapshot older than an hour is not trusted: what came since
// may be the owner's.
func recording(install, file string) string {
	return `d=$(dirname ` + file + `); mkdir -p "$d" || exit 1
b=` + file + `.before-$(printf '%s ' "$@" | cksum | cut -d' ' -f1)
if [ -z "$(find "$b" -mmin -60 2>/dev/null)" ]; then
` + installedNow + ` > "$b.tmp" && mv "$b.tmp" "$b" || exit 1
fi
` + install + `
rc=$?
` + installedNow + ` | LC_ALL=C comm -13 "$b" - >> ` + file + `
rm -f "$b"
exit $rc`
}
