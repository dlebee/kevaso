//go:build !linux && !darwin

package mesh

import (
	"errors"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Apply is for Linux (kernel WireGuard) and macOS (wireguard-go, userspace).
func Apply(Desired, wgtypes.Key, wgtypes.Key) error {
	return errors.New("the mesh needs Linux or macOS")
}
