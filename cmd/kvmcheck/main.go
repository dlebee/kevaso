// Command kvmcheck reports whether /dev/kvm is usable. The end-to-end loop copies it onto test
// machines; its last line is "PASS" or "FAIL: <reason>".
package main

import (
	"fmt"
	"os"

	"kevaso.com/core/internal/kvmcheck"
)

func main() {
	dev := "/dev/kvm"
	if len(os.Args) > 1 {
		dev = os.Args[1]
	}
	res, err := kvmcheck.Check(dev)
	if err == nil {
		err = res.Verify()
	}
	if err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
	fmt.Printf("KVM API version %d, VM created\nPASS\n", res.APIVersion)
}
