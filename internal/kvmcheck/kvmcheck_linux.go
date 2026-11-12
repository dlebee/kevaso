//go:build linux

package kvmcheck

import (
	"fmt"
	"os"
	"syscall"
)

const (
	kvmGetAPIVersion = 0xAE00 // _IO(KVMIO, 0x00)
	kvmCreateVM      = 0xAE01 // _IO(KVMIO, 0x01)
)

// Check opens dev (normally /dev/kvm) and runs the two ioctls.
func Check(dev string) (Result, error) {
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return Result{}, fmt.Errorf("open %s: %w", dev, err)
	}
	defer func() { _ = f.Close() }() // read-only use: nothing to flush
	v, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), kvmGetAPIVersion, 0)
	if errno != 0 {
		return Result{}, fmt.Errorf("KVM_GET_API_VERSION: %w", errno)
	}
	res := Result{APIVersion: int(v)}
	vm, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), kvmCreateVM, 0)
	if errno == 0 {
		res.CreatedVM = true
		_ = syscall.Close(int(vm)) // the VM was only a probe
	}
	return res, nil
}
