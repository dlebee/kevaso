//go:build !linux

package mesh

import (
	"errors"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Apply is Linux only (kernel WireGuard).
func Apply(Desired, wgtypes.Key, wgtypes.Key) error {
	return errors.New("the mesh needs Linux (kernel WireGuard)")
}
