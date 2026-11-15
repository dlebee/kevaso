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
