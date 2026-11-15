package kplugin

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// devicePart is one part of a device path: what udev and the kernel name devices with.
var devicePart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+@=,-]*$`)

// notDevices are paths under /dev that are no volume's block device: links to the reader's own
// files, pseudo file systems, and character devices a volume never is.
var notDevices = []string{"/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/shm", "/dev/pts", "/dev/mqueue",
	"/dev/hugepages", "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/mem", "/dev/kmem",
	"/dev/port", "/dev/kvm", "/dev/fuse", "/dev/tty", "/dev/console", "/dev/ptmx", "/dev/net", "/dev/vhost-net", "/dev/vfio"}

// DevicePathProblem says why dev can't be the device of an attached volume
// (AttachmentStatus.Device), or nil: it must be a clean absolute path under /dev, each part a
// plain device name, and not one of the paths under /dev that are no block device. Core refuses
// any other answer before it reaches a host. A stable name (/dev/disk/by-id/…) is what a plugin
// should answer; which forms core accepts beyond that is the contract's to say.
func DevicePathProblem(dev string) error {
	rest, ok := strings.CutPrefix(dev, "/dev/")
	if !ok || rest == "" || path.Clean(dev) != dev {
		return fmt.Errorf("device %q: a clean path under /dev", dev)
	}
	for _, p := range strings.Split(rest, "/") {
		if !devicePart.MatchString(p) {
			return fmt.Errorf("device %q: %q isn't a device name", dev, p)
		}
	}
	for _, n := range notDevices {
		if dev == n || strings.HasPrefix(dev, n+"/") {
			return fmt.Errorf("device %q: not a volume's block device", dev)
		}
	}
	return nil
}

// ByID is where a declared device prefix must be: names that stay with the disk across reboots
// and re-enumeration (a kernel name like /dev/sdb can name another disk tomorrow).
const ByID = "/dev/disk/by-id/"

// DevicePrefixProblem says why p can't be a plugin's declared device prefix, or nil: the start of
// a name under /dev/disk/by-id/ (at least one character of it, no further folder), so that a
// plugin's devices are names of its own, never the whole folder or a kernel name.
func DevicePrefixProblem(p string) error {
	rest, ok := strings.CutPrefix(p, ByID)
	if !ok || rest == "" || strings.Contains(rest, "/") || !devicePart.MatchString(rest) {
		return fmt.Errorf("device prefix %q: the start of a device's name under %s (e.g. %sscsi-0Linode_Volume_)", p, ByID, ByID)
	}
	return nil
}

// DeviceUnder says why dev isn't a device under one of the declared prefixes, or nil: a clean
// device path (DevicePathProblem), one prefix followed by a name of its own, nothing more.
func DeviceUnder(dev string, prefixes []string) error {
	if err := DevicePathProblem(dev); err != nil {
		return err
	}
	if len(prefixes) == 0 {
		return fmt.Errorf("device %q: the plugin declares no device prefix (devicePrefixes in its %s, which kvoadm plugin install --manifest stores on the host): it may attach no volume", dev, ManifestFile)
	}
	for _, p := range prefixes {
		if rest, ok := strings.CutPrefix(dev, p); ok && rest != "" && !strings.Contains(rest, "/") {
			return nil
		}
	}
	return fmt.Errorf("device %q: not under the plugin's declared prefix (%s)", dev, strings.Join(prefixes, ", "))
}
