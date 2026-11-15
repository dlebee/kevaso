package plugins

import (
	"context"
	"errors"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// devicePlugin answers AttachVolume with whatever device it is told.
type devicePlugin struct {
	Conn
	device string
}

func (d *devicePlugin) AttachVolume(context.Context, kplugin.Attachment) (kplugin.AttachmentStatus, error) {
	return kplugin.AttachmentStatus{Device: d.device}, nil
}

// K-038: a device path a plugin answers that isn't a clean device path is refused where the
// registry passes it on, with the plugin named; it never reaches the silo's status or the host.
func TestPluginDevicePathsAreChecked(t *testing.T) {
	for dev, ok := range map[string]bool{
		"/dev/disk/by-id/scsi-0Linode_Volume_x": true,
		"/etc/passwd":                           false,
		"/dev/../etc/shadow":                    false,
		"/dev/fd/3":                             false,
		"/dev/disk/by-id/x -o remount":          false,
		"":                                      false,
	} {
		r := &Registry{}
		_ = r.Add(context.Background(), &devicePlugin{Conn: kplugintest.New(), device: dev})
		p, _, _ := r.Storage(kplugintest.ClassBlock)
		at, err := p.Conn.AttachVolume(context.Background(), kplugin.Attachment{Class: kplugintest.ClassBlock, Handle: "vol-1"})
		if ok {
			if err != nil || at.Device != dev {
				t.Errorf("%q: %v %+v", dev, err, at)
			}
			continue
		}
		if !errors.Is(err, ErrBadAnswer) || !strings.Contains(err.Error(), "plugin fake: AttachVolume vol-1") || at.Device != "" {
			t.Errorf("%q passed on: %v %+v", dev, err, at)
		}
	}
}
