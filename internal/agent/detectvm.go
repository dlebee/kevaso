package agent

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// detectVM is DetectVM (the tests make it say bare metal, whatever machine runs them).
var detectVM = DetectVM

// DetectVM says whether this host is itself a virtual machine (K-093): systemd-detect-virt --vm
// where it is (exit 0: a VM), else the CPU's hypervisor flag (x86) or the firmware's names. A host
// that can't be told is taken for a VM: counting on both clocks only ever stops a silo sooner.
func DetectVM() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if p, err := exec.LookPath("systemd-detect-virt"); err == nil {
		err := exec.Command(p, "--vm", "--quiet").Run()
		if err == nil {
			return true
		}
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return false // it answered: not a VM
		}
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "flags") && strings.Contains(" "+l+" ", " hypervisor ") {
				return true
			}
		}
	}
	for _, f := range []string{"/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		v := strings.ToLower(string(b))
		for _, k := range []string{"qemu", "kvm", "vmware", "virtualbox", "xen", "microsoft corporation", "amazon ec2", "google", "linode", "digitalocean", "openstack", "bochs", "parallels"} {
			if strings.Contains(v, k) {
				return true
			}
		}
		return false // firmware names read: bare metal
	}
	return true
}
